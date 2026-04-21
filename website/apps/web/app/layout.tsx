import * as React from "react"
import type { Metadata } from "next"
import { Geist, Geist_Mono } from "next/font/google"

import "@workspace/ui/globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { Nav } from "@/components/nav"
import { cn } from "@workspace/ui/lib/utils"

const geist = Geist({ subsets: ["latin"], variable: "--font-sans" })

const fontMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
})

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env["NEXT_PUBLIC_SITE_URL"] ?? "https://inertia.chat"
  ),
  title: "Inertia",
  description:
    "A decentralised, cross-platform communication client for iOS. Built by humans, for humans.",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>): React.JSX.Element {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn(
        "antialiased",
        fontMono.variable,
        "font-sans",
        geist.variable
      )}
    >
      <body>
        <ThemeProvider>
          <Nav />
          <main className="container mx-auto max-w-3xl px-4 py-8">
            {children}
          </main>
          <footer className="border-t py-6 mt-8">
            <div className="container mx-auto max-w-3xl px-4 text-center text-sm text-muted-foreground">
              <p>Inertia is licensed under the MIT license.</p>
              <p className="mt-1">
                <a
                  href="/privacy"
                  className="hover:text-foreground underline underline-offset-4"
                >
                  Privacy Policy
                </a>
              </p>
            </div>
          </footer>
        </ThemeProvider>
      </body>
    </html>
  )
}
