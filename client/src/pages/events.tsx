import { MainLayout } from "@/components/layouts/MainLayout";
import { UpcomingEvents } from "@/components/sections/UpcomingEvents";

export default function Events() {
  return (
    <MainLayout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-bold mb-8">Our Events</h1>
        <UpcomingEvents />
      </div>
    </MainLayout>
  );
}
