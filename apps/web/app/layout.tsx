import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DevBox Agent Security Lab",
  description: "Authorized sandbox testing for managed and opt-in AI agents."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
