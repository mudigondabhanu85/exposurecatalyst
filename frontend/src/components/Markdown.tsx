import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Help Markdown links are written for MkDocs (relative .md paths); map them to /docs URLs in-app. */
function rewriteHref(href = ""): string {
  if (/^(https?:|mailto:|\/|#)/.test(href)) return href;
  const [path, hash] = href.split("#");
  if (!path.endsWith(".md")) return href;
  const parts = ["help"];
  for (const seg of path.replace(/\.md$/, "").split("/")) {
    if (seg === "..") parts.pop();
    else if (seg && seg !== ".") parts.push(seg);
  }
  const page = parts.join("/").replace(/(^|\/)index$/, "");
  return `/docs/${page}${page ? "/" : ""}${hash ? `#${hash}` : ""}`;
}

// react-markdown never renders raw HTML (no rehype-raw), so help content cannot inject markup.
export function Markdown({ source }: { source: string }) {
  return (
    <div className="prose-help">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => {
            const url = rewriteHref(href);
            const external = /^https?:/.test(url) || url.startsWith("/docs");
            return <a href={url} {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}>{children}</a>;
          },
        }}
      >
        {source}
      </ReactMarkdown>
    </div>
  );
}
