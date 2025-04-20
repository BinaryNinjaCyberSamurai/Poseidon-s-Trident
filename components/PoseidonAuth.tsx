"use client";
import React from "react";
import { Header } from "Header";
import { SecurityFeatures } from "SecurityFeatures";
import { LoginForm } from "LoginForm";
import { Footer } from "Footer";

export default function PoseidonAuth() {
  return (
    <main className="flex flex-col bg-slate-900 min-h-screen">
      <Header />
      <section className="flex gap-20 justify-center items-center px-6 flex-grow">
        <SecurityFeatures />
        <LoginForm />
      </section>
      <Footer />
    </main>
  );
}
