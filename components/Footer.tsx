import React from "react";

export const Footer = () => {
  const socialLinks = [
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/46052e5b7d8b06e216360a621c0b0e60a6807013",
      alt: "Facebook",
    },
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/01011f07816d695d221b9bdc6761513d6d4d1383",
      alt: "Twitter",
    },
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/7f88cfa7053ae9c781f710e3e15163b36bd7c35a",
      alt: "Instagram",
    },
  ];

  return (
    <footer className="p-6 mt-10 bg-slate-900">
      <div className="flex justify-between items-center max-sm:flex-col max-sm:gap-4">
        <p className="text-sm text-gray-400">
          © 2025 Poseidon's Trident. All rights reserved.
        </p>
        <nav className="flex gap-6 items-center">
          <a href="#" className="text-base text-gray-500">
            Privacy Policy
          </a>
          <a href="#" className="text-sm text-gray-500">
            Terms of Service
          </a>
          <a href="#" className="text-base text-gray-500">
            Contact
          </a>
        </nav>
        <div className="flex gap-4 items-center">
          {socialLinks.map((link, index) => (
            <a key={index} href="#" aria-label={link.alt}>
              <img
                src={link.icon}
                alt={link.alt}
                className="w-[18px] h-[17px]"
              />
            </a>
          ))}
        </div>
      </div>
    </footer>
  );
};
