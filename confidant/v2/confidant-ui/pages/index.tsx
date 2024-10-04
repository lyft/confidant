import Head from 'next/head'
import Image from 'next/image'
import { Inter } from 'next/font/google'
import styles from '@/styles/Home.module.css'
import ConfidantClient from './api/client'

const inter = Inter({ subsets: ['latin'] })

export default function Home() {
  let client = new ConfidantClient()
  client.healthcheck()
  return (
    <>
      <Head>
        <title>Confidant v2</title>
        <meta name="description" content="Confidant: your secret keeper." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/images/favicon.svg" />
      </Head>
      <main className={styles.main}>
          <Image
            className={styles.logo}
            src="/images/logo.svg"
            alt="Confidant logo"
            width={500}
            height={200}
            priority
          />
      </main>
    </>
  )
}
