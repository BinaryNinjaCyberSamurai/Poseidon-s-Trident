"use client";
import React, { useState } from "react";

export const LoginForm = () => {
  const [rememberMe, setRememberMe] = useState(false);
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle form submission
  };

  return (
    <section className="p-8 w-full rounded-xl border border-cyan-800 bg-cyan-950 max-w-[440px]">
      <h2 className="mb-3 text-3xl font-bold text-center text-zinc-200">
        Welcome Back
      </h2>
      <p className="mb-8 text-base text-center text-cyan-600">
        Sign in to your account
      </p>
      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        <div className="flex flex-col gap-2">
          <label htmlFor="email" className="text-xs text-gray-400">
            Email
          </label>
          <div className="relative">
            <input
              id="email"
              type="email"
              placeholder="Enter your email"
              className="pl-12 w-full text-base text-gray-500 rounded border border-cyan-800 bg-teal-950 h-[50px]"
              value={formData.email}
              onChange={(e) =>
                setFormData({ ...formData, email: e.target.value })
              }
            />
            <img
              src="https://cdn.builder.io/api/v1/image/assets/TEMP/839186bcb881a2ea89a2e8ad0a722ad3b9f61027"
              alt=""
              className="absolute left-[19px] top-[17px] w-[18px] h-[16px]"
            />
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <label htmlFor="password" className="text-xs text-gray-400">
            Password
          </label>
          <div className="relative">
            <input
              id="password"
              type="password"
              placeholder="Enter your password"
              className="pl-12 w-full text-base text-gray-500 rounded border border-cyan-800 bg-teal-950 h-[50px]"
              value={formData.password}
              onChange={(e) =>
                setFormData({ ...formData, password: e.target.value })
              }
            />
            <img
              src="https://cdn.builder.io/api/v1/image/assets/TEMP/c08b9ba8ba9e6e48a827699e98d66f0a078e9319"
              alt=""
              className="absolute left-[20px] top-[16px] w-[16px] h-[18px]"
            />
          </div>
        </div>
        <div className="flex justify-between items-center">
          <div className="flex gap-2 items-center">
            <input
              type="checkbox"
              id="remember"
              className="w-4 h-4"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
            />
            <label htmlFor="remember" className="text-xs text-gray-400">
              Remember me
            </label>
          </div>
          <a href="#" className="text-sm text-cyan-600">
            Forgot password?
          </a>
        </div>
        <button
          type="submit"
          className="w-full h-12 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded font-medium"
        >
          Sign In
        </button>
        <div className="flex gap-1 justify-center items-center mt-6">
          <p className="text-xs text-gray-400">Don't have an account?</p>
          <a href="#" className="text-sm text-cyan-600">
            Sign up
          </a>
        </div>
      </form>
    </section>
  );
};
