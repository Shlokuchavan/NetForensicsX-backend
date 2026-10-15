"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

type SearchContextValue = {
  query: string;
  setQuery: (value: string) => void;
  visible: boolean;
  setVisible: (value: boolean) => void;
};

const SearchContext = createContext<SearchContextValue | null>(null);

export function SearchProvider({ children }: { children: React.ReactNode }) {
  const [query, setQuery] = useState("");
  const [visible, setVisibleState] = useState(false);

  const setVisible = useCallback((value: boolean) => {
    setVisibleState(value);
    if (!value) setQuery("");
  }, []);

  const value = useMemo<SearchContextValue>(
    () => ({ query, setQuery, visible, setVisible }),
    [query, visible, setVisible]
  );

  return (
    <SearchContext.Provider value={value}>{children}</SearchContext.Provider>
  );
}

export function useSearch(): SearchContextValue {
  const context = useContext(SearchContext);
  if (!context) {
    throw new Error("useSearch must be used inside <SearchProvider>");
  }
  return context;
}