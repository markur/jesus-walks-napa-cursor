import { MainLayout } from "@/components/layouts/MainLayout";
import { Hero } from "@/components/sections/Hero";
import { Features } from "@/components/sections/Features";
import { UpcomingEvents } from "@/components/sections/UpcomingEvents";
import { Newsletter } from "@/components/sections/Newsletter";

export default function Home() {
  return (
    <MainLayout>
      <Hero />
      <Features />
      <UpcomingEvents />
      <Newsletter />
    </MainLayout>
  );
}
