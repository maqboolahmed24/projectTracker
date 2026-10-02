'use client';
import dynamic from 'next/dynamic';
const Product=dynamic(()=>import('../frontend/app'),{ssr:false,loading:()=> <div className="initial-shell" aria-label="Opening Maqbool"/>});
export default Product;
