import { Card, CardContent } from "@/components/ui/card";
import { Mountain, Users, Cross, Heart } from "lucide-react";

const features = [
  {
    title: "Guided Hikes",
    description: "Expert-led hikes for all skill levels through God's creation",
    icon: Mountain,
  },
  {
    title: "Community",
    description: "Connect with like-minded believers who share your passion",
    icon: Users,
  },
  {
    title: "Spiritual Growth",
    description: "Integrate faith and outdoor adventure in meaningful ways",
    icon: Cross,
  },
  {
    title: "Fellowship",
    description: "Build lasting friendships through shared experiences",
    icon: Heart,
  },
];

export function Features() {
  return (
    <div className="container mx-auto px-4 py-16">
      <h2 className="text-3xl font-bold text-center mb-12">Why Join Us</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {features.map((feature) => (
          <Card key={feature.title}>
            <CardContent className="pt-6">
              <div className="rounded-full bg-primary/10 w-12 h-12 flex items-center justify-center mb-4">
                <feature.icon className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">{feature.title}</h3>
              <p className="text-sm text-muted-foreground">{feature.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
