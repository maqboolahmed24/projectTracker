import type { Metadata } from 'next';
import '@fontsource-variable/inter';
import '../globals.css';
export const metadata:Metadata={title:'Maqbool: A shared place for your work',description:'Bring projects, people and progress together in one calm workspace.',robots:{index:false,follow:false},icons:{icon:'/brand/assets/maqbool-symbol.svg'}};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en" suppressHydrationWarning><body>{children}</body></html>;}
