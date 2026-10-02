import { connection } from 'next/server';
import Product from '../../frontend-entry';
export default async function Page(){await connection();return <Product/>;}
