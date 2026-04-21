import type { NextConfig } from "next"

const nextConfig: NextConfig = {
  transpilePackages: ["@workspace/ui"],
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "inertia.chat",
      },
      {
        protocol: "https",
        hostname: "img.shields.io",
      },
    ],
  },
}

export default nextConfig
