import Link from "next/link";

export default function NotFound() {
  return (
    <main style={{ padding: "2rem", maxWidth: "42rem", margin: "0 auto" }}>
      <h1>Page not found</h1>
      <p>The requested workspace page does not exist. No content was substituted.</p>
      <p><Link href="/">Return to overview</Link></p>
    </main>
  );
}
