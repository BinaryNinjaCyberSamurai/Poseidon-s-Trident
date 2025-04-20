import React from "react";

export const SecurityFeatures = () => {
  const features = [
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/f09cb16f4549c2eb727cd6b8a7a1b243b627e915",
      text: "256-bit Encryption",
    },
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/ffdaf0737aae715979cac3d31defbdaccde26ea3",
      text: "Advanced Firewall",
    },
    {
      icon: "https://cdn.builder.io/api/v1/image/assets/TEMP/6ea41b620b7c0ff21470baa5660d155112e11f54",
      text: "Threat Detection",
    },
  ];

  return (
    <article className="flex flex-col items-center text-center max-w-[600px]">
      <h1 className="mb-4 text-5xl font-bold text-gray-200">
        Poseidon's Trident
      </h1>
      <p className="mb-10 text-2xl text-cyan-500">Secure Your Digital Waters</p>
      <img
        src="https://cdn.builder.io/api/v1/image/assets/TEMP/4d0eeb7c06f56252e7322acdbb16729cec14948e"
        alt="Security Shield"
        className="w-[144px] h-[176px] mb-[40px]"
      />
      <div className="flex gap-10 justify-center items-center">
        {features.map((feature, index) => (
          <div key={index} className="flex flex-col items-center">
            <img
              src={feature.icon}
              alt={feature.text}
              className="w-[30px] h-[30px] mb-[8px]"
            />
            <p className="text-xs text-slate-500">{feature.text}</p>
          </div>
        ))}
      </div>
    </article>
  );
};
