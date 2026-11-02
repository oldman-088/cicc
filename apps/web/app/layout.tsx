import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'CICC | Command Center', description: 'Cyber Intelligence Command Center demonstration' };
export default function RootLayout({children}:{children:React.ReactNode}) { return <html lang="en"><body>{children}</body></html>; }
