import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "NetAudit - Linux Security Audit Tool",
  description: "Professional Linux network infrastructure security audit tool by CRYPTSK. Analyze sysctl, firewall, network, and security configurations.",
  keywords: ["Linux", "Security", "Audit", "Network", "Firewall", "Sysctl", "Hardening", "CRYPTSK"],
  authors: [{ name: "CRYPTSK Pvt Ltd" }],
  icons: {
    icon: "/logo.png",
  },
  openGraph: {
    title: "NetAudit - Linux Security Audit Tool",
    description: "Professional Linux network infrastructure security audit tool",
    url: "https://cryptsk.com",
    siteName: "NetAudit",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "NetAudit - Linux Security Audit Tool",
    description: "Professional Linux network infrastructure security audit tool",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
