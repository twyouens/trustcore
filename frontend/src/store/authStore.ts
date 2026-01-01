import { create } from 'zustand';
import { User } from '@/types';

interface AuthStore {
  token: string | null;
  user: User | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
  setUser: (user: User) => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  token: localStorage.getItem('trustcore_token'),
  user: null,
  isAuthenticated: !!localStorage.getItem('trustcore_token'),
  
  login: (token: string) => {
    localStorage.setItem('trustcore_token', token);
    set({ token, isAuthenticated: true });
  },
  
  logout: () => {
    localStorage.removeItem('trustcore_token');
    set({ token: null, user: null, isAuthenticated: false });
  },
  
  setUser: (user: User) => {
    set({ user });
  },
}));