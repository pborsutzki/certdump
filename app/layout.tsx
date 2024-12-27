import "./globals.css";

export const metadata = {
  title: "Certificate chain dump API endpoint",
  description: "Certificate chain dump API endpoint",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
