import { useEffect, useState, useCallback } from "react";

export type Theme = "light" | "dark";
const STORAGE_KEY = "owlsec.theme";

function readInitial(): Theme {
  if (typeof document === "undefined") return "dark";
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

function apply(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setThemeState(readInitial());
    setMounted(true);
  }, []);

  const setTheme = useCallback((next: Theme) => {
    apply(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* ignore */
    }
    setThemeState(next);
  }, []);

  const toggle = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [theme, setTheme]);

  return { theme, setTheme, toggle, mounted };
}

// Inline script that runs before hydration to prevent FOUC.
export const themeInitScript = `
(function(){try{
  var s=localStorage.getItem("owlsec.theme");
  var t = s === 'light' || s === 'dark' ? s : 'dark';
  var r=document.documentElement;
  if(t==='dark')r.classList.add('dark');else r.classList.remove('dark');
  r.style.colorScheme=t;
}catch(e){}})();
`;
