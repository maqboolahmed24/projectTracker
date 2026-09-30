'use client';
import { createContext, useContext } from 'react';
import type { ClientRuntime } from '../../src/client/runtime.js';
import type { ReadablePlanning } from '../../src/client/planning-crypto.js';
import type { WorkspaceDirectory } from '../../src/client/directory-crypto.js';
export type { WorkspaceDirectory };
export type Theme = 'light'|'dark'|'system';
export interface AppRoute {page:'home'|'projects'|'my-work'|'inbox'|'project'|'settings';projectId?:string;taskId?:string;phaseId?:string;tab?:string;section?:string}
export interface AppContextValue {
  client:ClientRuntime;
  directory:WorkspaceDirectory|null;
  projects:ReadablePlanning[];
  reloadDirectory:()=>Promise<void>;
  reloadProjects:()=>Promise<void>;
  navigate:(route:AppRoute|string)=>void;
  notify:(message:string,tone?:'success'|'error'|'info')=>void;
  theme:Theme;
  setTheme:(theme:Theme)=>void;
  signOut:()=>Promise<void>;
  openApprovals:(handoff?:string,onDone?:()=>void|Promise<void>)=>void;
}
export const AppContext=createContext<AppContextValue|null>(null);
export function useApp(){const value=useContext(AppContext);if(!value)throw new Error('Application context is unavailable');return value;}
