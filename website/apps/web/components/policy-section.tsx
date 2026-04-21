import * as React from "react"
import type { ReactNode } from "react"
import { Separator } from "@workspace/ui/components/separator"

interface PolicySectionProps {
  id: string
  /** Section heading — accepts a string or JSX (e.g. a title that contains <code>). */
  title: ReactNode
  children: ReactNode
}

/**
 * Renders a privacy-policy section with a sticky-nav-aware anchor, a heading,
 * and a separator rule below the content. Add a new section by dropping in
 * another <PolicySection> — no need to touch heading styles or separators.
 */
export function PolicySection({ id, title, children }: PolicySectionProps): React.JSX.Element {
  return (
    <>
      <section id={id} className="scroll-mt-20">
        <h2 className="text-lg font-semibold mb-3">{title}</h2>
        {children}
      </section>
      <Separator />
    </>
  )
}
