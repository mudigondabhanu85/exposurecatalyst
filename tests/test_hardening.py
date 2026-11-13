from __future__ import annotations

from datetime import timedelta

from cryptography.fernet import Fernet

from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.maintenance import retention, rotate_secrets, run_daily
from exposurecatalyst.models import AiProvider, AppSetting, Integration, JobRun, User, UserSession
from exposurecatalyst.security import crypto
from exposurecatalyst.security.crypto import SecretBox


def test_key_rotation_reencrypts_everything(db):
    old, new = Fernet.generate_key(), Fernet.generate_key()
    old_box = SecretBox(old)
    db.add(User(username="u1", totp_secret_enc=old_box.encrypt("TOTPSEED")))
    db.add(Integration(kind="wiz", name="W", base_url="https://api.app.wiz.io", config={}, state={},
                       secrets_enc=old_box.encrypt('{"client_secret": "s"}')))
    db.add(AiProvider(kind="openai", name="O", base_url="https://api.openai.com/v1", default_model="m", models=[],
                      config={}, secrets_enc=old_box.encrypt('{"api_key": "k"}')))
    db.add(AppSetting(key="smtp", value={"host": "h", "password_enc": old_box.encrypt("pw")}))
    db.commit()
    rotating = SecretBox(new, [old])  # new primary + old accepted for decryption
    counts = rotate_secrets(db, rotating)
    assert counts["users.totp"] == 1 and counts["integrations"] == 1 and counts["ai_providers"] == 1 and counts["smtp"] == 1
    only_new = SecretBox(new)  # after rotation the old key can be dropped
    assert only_new.decrypt(db.query(User).filter_by(username="u1").one().totp_secret_enc) == "TOTPSEED"
    assert only_new.decrypt(db.get(AppSetting, "smtp").value["password_enc"]) == "pw"
    assert "client_secret" in only_new.decrypt(db.query(Integration).one().secrets_enc)


def test_rotation_dry_run_changes_nothing(db):
    old = Fernet.generate_key()
    token = SecretBox(old).encrypt("x")
    db.add(User(username="u2", totp_secret_enc=token))
    db.commit()
    rotate_secrets(db, SecretBox(Fernet.generate_key(), [old]), dry_run=True)
    assert db.query(User).filter_by(username="u2").one().totp_secret_enc == token


def test_settings_previous_keys_used(settings, monkeypatch):
    old, new = Fernet.generate_key(), Fernet.generate_key()
    token = SecretBox(old).encrypt("hello")
    from pydantic import SecretStr

    s = settings.model_copy(update={"encryption_key": SecretStr(new.decode()), "encryption_keys_previous": SecretStr(old.decode())})
    assert crypto.build_secret_box(s).decrypt(token) == "hello"


def test_retention_and_daily_guard(db, settings, db_factory):
    now = utcnow()
    u = User(username="r1")
    db.add(u)
    db.flush()
    db.add_all([UserSession(token_hash="a" * 64, user_id=u.id, csrf_token="c", expires_at=now - timedelta(days=60)),
                UserSession(token_hash="b" * 64, user_id=u.id, csrf_token="c", expires_at=now + timedelta(hours=1)),
                JobRun(source="nvd", trigger="cli", started_at=now - timedelta(days=200)),
                JobRun(source="nvd", trigger="cli", started_at=now)])
    db.commit()
    assert retention(db, settings)["sessions"] == 1
    db.commit()
    assert db.query(UserSession).count() == 1 and db.query(JobRun).count() == 1
    assert run_daily(settings, get_session_factory()) is not None
    assert run_daily(settings, get_session_factory()) is None  # at most once per 24 h
