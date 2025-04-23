import { AdminLayout } from "@/components/layouts/AdminLayout";
import { Button } from "@/components/ui/button";
import { PlusIcon } from "lucide-react";
import { useQuery, useMutation } from "@tanstack/react-query";
import type { Product } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";

export default function AdminProducts() {
  const { toast } = useToast();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [imageUrl, setImageUrl] = useState("");
  const [isPreviewValid, setIsPreviewValid] = useState(false);

  const { data: products, isLoading } = useQuery<Product[]>({
    queryKey: ["/api/products"],
  });

  const createProduct = useMutation({
    mutationFn: async (formData: FormData) => {
      // Extract form data and ensure proper type conversion
      const name = formData.get("name")?.toString();
      const description = formData.get("description")?.toString();
      const priceStr = formData.get("price")?.toString();
      const category = formData.get("category")?.toString();
      const stockStr = formData.get("stock")?.toString();

      if (!name || !description || !priceStr || !category || !stockStr || !imageUrl) {
        throw new Error("All fields are required");
      }

      const price = parseFloat(priceStr);
      const stock = parseInt(stockStr);

      if (isNaN(price) || price <= 0) {
        throw new Error("Please enter a valid price");
      }

      if (isNaN(stock) || stock < 0) {
        throw new Error("Please enter a valid stock quantity");
      }

      const product = {
        name,
        description,
        price: price.toString(), // Convert to string for decimal compatibility
        imageUrl,
        category,
        stock,
      };

      await apiRequest("POST", "/api/products", product);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Product created successfully",
      });
      setIsDialogOpen(false);
      setImageUrl("");
      setIsPreviewValid(false);
      queryClient.invalidateQueries({ queryKey: ["/api/products"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleImagePreview = (url: string) => {
    setImageUrl(url);
    const img = new Image();
    img.onload = () => setIsPreviewValid(true);
    img.onerror = () => setIsPreviewValid(false);
    img.src = url;
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!isPreviewValid) {
      toast({
        title: "Error",
        description: "Please provide a valid image URL",
        variant: "destructive",
      });
      return;
    }
    const formData = new FormData(e.currentTarget);
    createProduct.mutate(formData);
  };

  if (isLoading) {
    return (
      <AdminLayout>
        <div className="animate-pulse space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-24 bg-muted rounded-lg" />
          ))}
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Products</h1>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <PlusIcon className="h-4 w-4 mr-2" />
              Add Product
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Add New Product</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="name">Name</Label>
                <Input id="name" name="name" required />
              </div>
              <div>
                <Label htmlFor="description">Description</Label>
                <Input id="description" name="description" required />
              </div>
              <div>
                <Label htmlFor="price">Price</Label>
                <Input 
                  id="price" 
                  name="price" 
                  type="number" 
                  step="0.01" 
                  min="0" 
                  required 
                />
              </div>
              <div>
                <Label htmlFor="imageUrl">Image URL</Label>
                <div className="flex gap-2">
                  <Input 
                    id="imageUrl"
                    value={imageUrl}
                    onChange={(e) => handleImagePreview(e.target.value)}
                    placeholder="Enter image URL or paste from clipboard"
                    required 
                  />
                </div>
                {imageUrl && (
                  <div className="mt-2">
                    {isPreviewValid ? (
                      <div className="relative w-full h-48 rounded-lg overflow-hidden">
                        <img 
                          src={imageUrl} 
                          alt="Product preview" 
                          className="w-full h-full object-cover"
                        />
                        <div className="absolute top-2 right-2">
                          <span className="bg-green-500 text-white px-2 py-1 rounded-full text-xs">
                            Valid Image
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-red-50 text-red-500 p-2 rounded">
                        Invalid image URL. Please check the URL and try again.
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div>
                <Label htmlFor="category">Category</Label>
                <Input id="category" name="category" required />
              </div>
              <div>
                <Label htmlFor="stock">Stock</Label>
                <Input 
                  id="stock" 
                  name="stock" 
                  type="number" 
                  min="0" 
                  required 
                />
              </div>
              <Button 
                type="submit" 
                className="w-full mb-4"
                disabled={createProduct.isPending || !isPreviewValid}
              >
                {createProduct.isPending ? "Creating..." : "Create Product"}
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {products?.map((product) => (
          <Card key={product.id}>
            <CardContent className="p-4">
              <img
                src={product.imageUrl}
                alt={product.name}
                className="w-full h-48 object-cover rounded-lg mb-4"
              />
              <h3 className="font-semibold">{product.name}</h3>
              <p className="text-sm text-muted-foreground">{product.description}</p>
              <div className="mt-2 flex justify-between items-center">
                <span className="font-bold">${Number(product.price).toFixed(2)}</span>
                <span className="text-sm text-muted-foreground">
                  Stock: {product.stock}
                </span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </AdminLayout>
  );
}