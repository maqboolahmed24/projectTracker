'use client';
import { ArrowRight, Files, Folder, ListTodo, ShieldCheck } from 'lucide-react';
import { useApp, type AppRoute } from './context';
import { Button, Modal } from './ui';
import { projectName } from '../work/shared';

/** Guidance stays close to the current work and only links to available screens. */
export function WorkspaceGuidance({route,onClose}:{route:AppRoute;onClose:()=>void}){
  const {directory,projects,navigate}=useApp(),project=projects.find(row=>row.graph.project.id===route.projectId);
  const open=(next:AppRoute)=>{onClose();navigate(next);};
  const work=project?{page:'project' as const,projectId:project.graph.project.id,tab:'work'}:{page:'projects' as const};
  const fileView=!!project&&route.page==='project'&&['files','delivery'].includes(route.tab??'');
  return <Modal open onClose={onClose} title="A little guidance" description={project?`A clear next step in ${projectName(project)}.`:'Find your next step and keep your team moving.'}>
    <div className="guide-list assisted-guide">
      <div><Folder aria-hidden="true"/><h3>{project?'Start when the team is ready':'Give your work a home'}</h3><p>{project?'A planned project is a place to prepare tasks and waves. Start the project to let people begin. Each wave can start when its own work is ready.':'Create a project, add a task and choose the people working on it. Start the project when you are ready to begin.'}</p><Button variant="secondary" onClick={()=>open(project?{...work,tab:'overview'}:{page:'projects'})}>{project?'Open project overview':'Browse projects'} <ArrowRight size={15}/></Button></div>
      <div><ListTodo aria-hidden="true"/><h3>{route.page==='my-work'?'Your work, in one place':'Know what happens next'}</h3><p>Open a task to see who is working on it and what needs to happen next. When review is required, the assigned reviewer approves the finished work. Discussion stays with the task.</p><Button variant="secondary" onClick={()=>open(project?work:{page:'my-work'})}>{project?'Open project work':'Open My work'} <ArrowRight size={15}/></Button></div>
      {fileView?<div><Files aria-hidden="true"/><h3>From source to finished work</h3><p>Sources are the documents you work from. Outputs are the files you produce. Add an updated file after editing outside Maqbool; shared-drive references do not sync automatically. Approved outputs can be prepared for delivery by an Owner.</p><Button variant="secondary" onClick={()=>open({...work,tab:'files'})}>Open project files <ArrowRight size={15}/></Button></div>:<div><ShieldCheck aria-hidden="true"/><h3>{directory?.isOwner?'Bring the right people in':'Your account, on another device'}</h3><p>{directory?.isOwner?'Invite someone from People and ask them to open their link. Open Access requests, start the security check and complete it together. Then give them the project access they need.':'Create a private sign-in link in Your account and open it on your other device. Enter your password there, then open its request here. Follow the password and matching-code checks on both devices; an Owner can help if you cannot use an approved device.'}</p><Button variant="secondary" onClick={()=>open({page:'settings',section:directory?.isOwner?'people':'security'})}>{directory?.isOwner?'Open People':'Open your account'} <ArrowRight size={15}/></Button></div>}
    </div>
  </Modal>;
}
