import * as React from "react"
import Link from "next/link"
import { FaGithub } from "react-icons/fa"
import { Button } from "@workspace/ui/components/button"

const linkClass = "text-muted-foreground hover:text-foreground transition-colors"

export function Nav(): React.JSX.Element {
  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto flex h-14 max-w-3xl items-center px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <span className="text-primary">Inertia for iOS</span>
        </Link>
        <nav className="ml-auto flex items-center gap-4 text-sm">
          <Link href="/" className={linkClass}>Home</Link>
          <Link href="/privacy" className={linkClass}>Privacy</Link>
          <Link
            href="https://github.com/psharma04/inertia"
            target="_blank"
            rel="noopener noreferrer"
            className={linkClass}
            aria-label="GitHub repository"
          >
            <FaGithub className="h-4 w-4" />
          </Link>
          <Button asChild size="sm">
            <Link
              href="https://testflight.apple.com/join/TNCkZ6KX"
              target="_blank"
              rel="noopener noreferrer"
            >
              Join TestFlight
            </Link>
          </Button>
        </nav>
      </div>
    </header>
  )
}
