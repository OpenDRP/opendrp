import { Moon, Sun, Laptop } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useTheme, type Theme } from "@/components/Theme/ThemeProvider";

const options: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Laptop },
];

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  const Icon =
    theme === "light" ? Sun : theme === "dark" ? Moon : Laptop;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 hover:bg-accent text-foreground"
          aria-label="Toggle theme"
        >
          <Icon className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        {options.map(({ value, label, icon: OptIcon }) => (
          <DropdownMenuItem
            key={value}
            onClick={() => setTheme(value)}
            className="gap-2 cursor-pointer"
          >
            <OptIcon className="h-4 w-4" />
            <span className="flex-1">{label}</span>
            {theme === value && (
              <span className="ml-auto text-xs text-muted-foreground">✓</span>
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
