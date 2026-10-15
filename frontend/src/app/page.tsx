

import { Dashboard } from "@/components/dashboard";

export default function Home() {
  return (
    <div className="flex min-h-screen bg-background">
     
      <div className="min-w-0 flex-1">
      
        <main>
          <Dashboard />
        </main>
      </div>
    </div>
  );
}
