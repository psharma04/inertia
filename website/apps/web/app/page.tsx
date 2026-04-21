import * as React from "react"
import type { ReactNode } from "react"
import Image from "next/image"
import Link from "next/link"
import { CheckCircle2, Circle, ExternalLink } from "lucide-react"
import { Badge } from "@workspace/ui/components/badge"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@workspace/ui/components/accordion"
import { Card, CardContent } from "@workspace/ui/components/card"
import { Separator } from "@workspace/ui/components/separator"
import { Button } from "@workspace/ui/components/button"
import { roadmapItems, faqItems, buildSteps, donationLinks } from "@/lib/home-data"

// --- shared sub-components -------------------------------------------------

function PageSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4">
      <h2 className="text-xl font-semibold">{title}</h2>
      {children}
    </section>
  )
}

function ExternalButton({
  href,
  size = "default",
  children,
}: {
  href: string
  size?: "default" | "sm"
  children: ReactNode
}) {
  return (
    <Button asChild variant="outline" size={size}>
      <Link href={href} target="_blank" rel="noopener noreferrer">
        {children} <ExternalLink className={size === "sm" ? "ml-1 h-3 w-3" : "ml-1 h-4 w-4"} />
      </Link>
    </Button>
  )
}

// --- page ------------------------------------------------------------------

export default function Page(): React.JSX.Element {
  return (
    <main className="mx-auto max-w-4xl px-4 py-10 flex flex-col gap-10">

      {/* Hero */}
      <section className="flex flex-col gap-6">
        <Image
          src="/assets/banner/gh-banner.png"
          alt="Inertia banner"
          width={1200}
          height={300}
          className="w-full rounded-lg object-cover"
          priority
        />

        <div className="flex flex-wrap gap-2">
          <Image src="https://img.shields.io/github/commit-activity/m/psharma04/inertia" alt="GitHub commit activity" height={20} width={0} style={{ width: "auto" }} unoptimized />
          <Image src="https://img.shields.io/github/issues/psharma04/inertia" alt="GitHub issues" height={20} width={0} style={{ width: "auto" }} unoptimized />
          <Image src="https://img.shields.io/badge/License-MIT-blue?cacheSeconds=36000" alt="Licenced under MIT Licence" height={20} width={0} style={{ width: "auto" }} unoptimized />
        </div>

        <div>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Inertia</h1>
          <p className="mt-2 text-lg text-muted-foreground">
            An decentralised, cross-platform communication client for iOS.<br /> Built by humans, for humans.
          </p>
        </div>

        <p className="text-sm leading-relaxed">
          Inertia is a pure Swift client for Reticulum, LXMF, and NomadNet. It&apos;s designed to provide
          a simple entrypoint for privacy-conscious people to try out a truly decentralised network,
          without needing to buy new gear.
        </p>

        <Card className="border-destructive bg-destructive/10">
          <CardContent className="pt-4 text-sm">
            <span className="font-bold">⚠️ ALPHA SOFTWARE:</span> DO NOT RELY ON THIS FOR CRITICAL
            COMMUNICATION, AND EXPECT YOUR DATA TO BE LOST EVERY TIME A NEW VERSION IS INSTALLED.
          </CardContent>
        </Card>
      </section>

      <Separator />

      {/* Features */}
      <PageSection title="Features">
        <ul className="list-disc list-inside space-y-2 text-sm leading-relaxed">
          <li>Send and receive encrypted messages without relying on traditional cloud providers</li>
          <li>Communicate with users on other clients (Sideband, MeshChat, Columba)</li>
        </ul>
      </PageSection>

      <Separator />

      {/* Roadmap — edit items in lib/home-data.ts */}
      <PageSection title="Roadmap">
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {roadmapItems.map((item) => (
            <div key={item.label} className="flex items-start gap-2 text-sm">
              {item.done ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-500" />
              ) : (
                <Circle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
              )}
              <span className={item.done ? "" : "text-muted-foreground"}>{item.label}</span>
            </div>
          ))}
        </div>
      </PageSection>

      <Separator />

      {/* FAQ — edit Q&A in lib/home-data.ts */}
      <PageSection title="FAQ">
        <Accordion type="single" collapsible className="w-full">
          {faqItems.map((item, i) => (
            <AccordionItem key={item.q} value={`faq-${i}`}>
              <AccordionTrigger className="text-sm font-medium text-left">
                {item.q}
              </AccordionTrigger>
              <AccordionContent className="text-sm text-muted-foreground">
                {item.a}
              </AccordionContent>
            </AccordionItem>
          ))}

          {/* "Can I give you money?" has buttons instead of plain text */}
          <AccordionItem value="faq-donate">
            <AccordionTrigger className="text-sm font-medium text-left">
              Can I give you money?
            </AccordionTrigger>
            <AccordionContent>
              <div className="flex flex-wrap gap-2 pt-1">
                {donationLinks.map(({ label, href }) => (
                  <ExternalButton key={href} href={href} size="sm">{label}</ExternalButton>
                ))}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </PageSection>

      <Separator />

      {/* Contact */}
      <PageSection title="Contact">
        <ul className="space-y-2 text-sm">
          <li>
            <span className="font-medium">Matrix (preferred):</span>{" "}
            <Link
              href="https://matrix.to/#/#inertia:inyourair.space"
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-4 hover:text-foreground text-muted-foreground"
            >
              #inertia:inyourair.space
            </Link>
          </li>
          <li>
            <span className="font-medium">LXMF:</span>{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
              3662d822203188617b2e44f2908b0bb3
            </code>
          </li>
        </ul>
      </PageSection>

      <Separator />

      {/* Building — edit steps in lib/home-data.ts */}
      <PageSection title="Building">
        <p className="text-sm text-muted-foreground">
          Requires iOS &gt;26.0 and XCode &gt;26.0. Dependencies managed by SPM.
        </p>
        <ol className="list-decimal list-inside space-y-2 text-sm">
          {buildSteps.map((step, i) => (
            <li key={i}>
              {step.kind === "cmd" ? (
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{step.value}</code>
              ) : (
                step.value
              )}
            </li>
          ))}
        </ol>
        <p className="text-sm text-muted-foreground">
          Pull requests are more than welcome (see{" "}
          <Link
            href="https://github.com/users/psharma04/projects/5"
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-4 hover:text-foreground"
          >
            project board
          </Link>
          ), but AI usage in any manner will result in the PR being ignored and immediately closed.
        </p>
      </PageSection>

      <Separator />

      {/* Sponsors — links shared with FAQ above via lib/home-data.ts */}
      <PageSection title="Help fund Inertia">
        <div className="flex flex-wrap gap-2">
          {donationLinks.map(({ label, href }) => (
            <ExternalButton key={href} href={href}>{label}</ExternalButton>
          ))}
        </div>
      </PageSection>

      <Separator />

      {/* Licensing */}
      <PageSection title="Licensing">
        <p className="text-sm leading-relaxed text-muted-foreground">
          All contents of the repository are licensed under the MIT license. Content considered artistic
          works, such as icons, are dual-licensed under MIT and CC-BY-4.0. This covers any files in the{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">assets/</code> folder, and
          any copies of those files elsewhere in the project.
        </p>
        <p className="text-sm text-muted-foreground">
          <Link
            href="https://github.com/jedisct1/swift-sodium"
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-4 hover:text-foreground"
          >
            Swift-Sodium
          </Link>{" "}
          is licensed under the ISC licence, which is considered compatible with the MIT license.
        </p>
      </PageSection>

      <Separator />

      {/* Powered by */}
      <footer className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
        <span>Powered by:</span>
        <Link href="https://github.com/markqvist/Reticulum" target="_blank" rel="noopener noreferrer">
          <Badge variant="secondary">Reticulum</Badge>
        </Link>
        <Link href="https://github.com/markqvist/LXMF" target="_blank" rel="noopener noreferrer">
          <Badge variant="secondary">LXMF</Badge>
        </Link>
        <Link href="https://github.com/markqvist/nomadnet" target="_blank" rel="noopener noreferrer">
          <Badge variant="secondary">NomadNet</Badge>
        </Link>
      </footer>

    </main>
  )
}
