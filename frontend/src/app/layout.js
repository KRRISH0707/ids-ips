import './globals.css';
import { TimeRangeProvider } from '@/context/TimeRangeContext';
import { ToastContainer } from '@/components/ToastContainer';
import { GlobalSearch } from '@/components/GlobalSearch';
import HorizontalScrollHelper from '@/components/HorizontalScrollHelper';

export const metadata = {
  title: 'Apex Sentinel // Autonomous Threat Defense Platform',
  description: 'Enterprise IDS/IPS & Next-Gen Autonomous Threat Defense Platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className="bg-grid">
        <TimeRangeProvider>
          <HorizontalScrollHelper />
          {children}
          <ToastContainer />
          <GlobalSearch />
        </TimeRangeProvider>
      </body>
    </html>
  );
}

