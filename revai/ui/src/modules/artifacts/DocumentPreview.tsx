import DOMPurify from 'isomorphic-dompurify'
import { marked } from 'marked'
import { useMemo } from 'react'

marked.setOptions({
  gfm: true,
  breaks: false,
})

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function slugify(text: string) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
}

/** Safe MD → HTML for analyst reports. */
export function renderMarkdown(src: string): string {
  try {
    const raw = marked.parse(src, { async: false }) as string
    return DOMPurify.sanitize(raw, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ['id'],
    })
  } catch (e) {
    return `<pre class="raw-doc">${escapeHtml(String(e))}\n\n${escapeHtml(src)}</pre>`
  }
}

export function extractToc(md: string): Array<{ id: string; text: string; level: number }> {
  const toc: Array<{ id: string; text: string; level: number }> = []
  for (const line of md.split('\n')) {
    const m = /^(#{1,3})\s+(.+)$/.exec(line.trim())
    if (!m) continue
    const text = m[2].replace(/[#*`]/g, '').trim()
    toc.push({ id: slugify(text), text, level: m[1].length })
  }
  return toc.slice(0, 40)
}

/** Inject ids into h1–h3 for TOC anchors. */
function addHeadingIds(html: string): string {
  return html.replace(/<h([1-3])>([\s\S]*?)<\/h\1>/gi, (_m, level, inner) => {
    const text = inner.replace(/<[^>]+>/g, '').trim()
    const id = slugify(text)
    return `<h${level} id="${id}">${inner}</h${level}>`
  })
}

export function DocumentPreview({
  path,
  text,
  mode,
  showToc = true,
  loading = false,
}: {
  path: string
  text: string
  mode: 'rendered' | 'raw'
  showToc?: boolean
  loading?: boolean
}) {
  const isMd = /\.(md|markdown)$/i.test(path)
  const isJson = /\.json$/i.test(path)

  const body = useMemo(() => {
    if (mode === 'raw' || (!isMd && !isJson)) {
      return { html: `<pre class="raw-doc">${escapeHtml(text)}</pre>`, kind: 'raw' as const, toc: [] as ReturnType<typeof extractToc> }
    }
    if (isJson) {
      try {
        const pretty = JSON.stringify(JSON.parse(text), null, 2)
        return { html: `<pre class="raw-doc">${escapeHtml(pretty)}</pre>`, kind: 'raw' as const, toc: [] }
      } catch {
        return { html: `<pre class="raw-doc">${escapeHtml(text)}</pre>`, kind: 'raw' as const, toc: [] }
      }
    }
    const toc = extractToc(text)
    return { html: addHeadingIds(renderMarkdown(text)), kind: 'md' as const, toc }
  }, [text, mode, isMd, isJson])

  const showTocRail = showToc && body.kind === 'md' && body.toc.length > 2

  return (
    <div style={{ display: 'grid', gridTemplateColumns: showTocRail ? '1fr 200px' : '1fr', gap: 'var(--sp-4)', alignItems: 'start' }}>
      <div className="reader-doc" style={{ opacity: loading ? 0.5 : 1 }}>
        {body.kind === 'raw' ? (
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: 'var(--tx-sm)' }}
            dangerouslySetInnerHTML={{ __html: body.html.replace(/^<pre class="raw-doc">/, '').replace(/<\/pre>$/, '') }}
          />
        ) : (
          <div dangerouslySetInnerHTML={{ __html: body.html }} />
        )}
      </div>
      {showTocRail && (
        <nav className="reader-toc" aria-label="Report sections">
          <div className="rail-label" style={{ padding: '0 0 6px 8px' }}>Outline</div>
          {body.toc.map((t) => (
            <a
              key={t.id + t.text}
              className={`toc-item${t.level === 3 ? ' h3' : ''}`}
              href={`#${t.id}`}
            >
              {t.text}
            </a>
          ))}
        </nav>
      )}
    </div>
  )
}
