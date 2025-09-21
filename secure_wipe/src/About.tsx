import React from "react";

const About = () => {
  return (
    <section className="whyuse-container" id="about">
      {/* Left Image */}
      <div className="whyuse-image">
        <img src="/images/secure-wipe.png" alt="Secure Wiping" />
      </div>

      {/* Right Content */}
      <div className="whyuse-content">
  <h2>Why use <span>TraceZero?</span></h2>
  <p>
    In India, over <span>1.75 million tonnes of e-waste</span> is generated every year, yet millions of laptops and smartphones remain locked away in homes and offices. The biggest reason?<span> Fear of data breaches.</span> Users worry that sensitive personal or organizational information could be recovered if they recycle or sell their old devices.
  </p>
  <p>
    TraceZero was built to solve this problem. Unlike existing data sanitization tools that are either too complex, expensive, or unreliable, TraceZero offers a <span>simple, secure, and tamper-proof data wiping solution.</span> With just one click, it permanently erases data from hard drives, SSDs, smartphones, and even hidden storage areas — while providing a <span>digitally signed wipe certificate</span> as proof of erasure.
  </p>
  <p>
    By making certified data wiping accessible to everyone, TraceZero empowers users to safely recycle their devices, reduces IT asset hoarding worth over <span>₹50,000 crore</span>, and contributes directly to <span>India’s circular economy</span> and sustainable e-waste management.
  </p>
</div>
    </section>
  );
};

export default About;
