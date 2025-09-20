import { useState, useEffect } from "react";
import "./App.css";
import About from "./About";
import FeaturesSection from "./FeaturesSection";

interface LoginModalProps {
  onLogin: () => void;
}
export default function LandingPage({onLogin}: LoginModalProps) {
  const slides = [
    {
      title: "Tamper-Proof Certificates",
      description: "Every wipe comes with a verifiable, audit-ready certificate ensuring compliance and trust.",
      image: "/images/certificate.png",
    },
    {
      title: "Cross-Platform Erasure",
      description: "Securely erase HDD, SSD, and USB devices across Windows, Linux, and Android environments.",
      image: "/images/platforms.png",
    },
    {
      title: "NIST 800-88 Certified",
      description: "Our methods follow international standards for data erasure with guaranteed security.",
      image: "/images/nist.png",
    },
    {
      title: "One-Click Simplicity",
      description: "Designed for enterprises & individuals with an easy one-click erasure process.",
      image: "/images/oneClick.png",
    },
    {
      title: "Audit-Ready Reports",
      description: "Generate reports instantly for ITAD, compliance, and enterprise data policies.",
      image: "/images/audit.png",
    },
  ];

  const [current, setCurrent] = useState(0);

  useEffect(() => {
    const interval = setInterval(
      () => setCurrent((prev) => (prev + 1) % slides.length),
      5000
    );
    return () => clearInterval(interval);
  }, [slides.length]);

  return (
    <div className="landing">
      {/* Navbar */}
      <header className="navbar">
        <h1>TraceZero</h1>
        <nav>
          <a href="#about">About Us</a>
          <a href="#solutions">Solutions</a>
          <a href="#faq">FAQ's</a>
          <a href="#contact">Contact</a>
        </nav>
      </header>

      {/* Hero Section */}
      <div className="slide">
      <section className="hero">
        <div className="hero-left fade-in">
          <h2>{slides[current].title}</h2>
          <p>{slides[current].description}</p>
          <div className="buttons">
            <button className="button-primary" onClick={onLogin}>Login / Register</button>
            <button className="button-secondary">Download App</button>
          </div>
        </div>
        <div className="hero-right fade-in">
          <img src={slides[current].image} alt={slides[current].title} />
        </div>
      </section>
      <div className="slider-dots">
        {slides.map((_, i) => (
          <div
            key={i}
            className={`dot ${i === current ? "active" : ""}`}
            onClick={() => setCurrent(i)}
          ></div>
        ))}
      </div>
      </div>
      <About/>
      <FeaturesSection/>
      <footer className="LandingFooter" id="contact">
        <nav className="LandingFooter-links">
          <a href="#">About</a>
          <a href="#">Contact</a>
          <a href="#">Help</a>
        </nav>
        <small style={{color:"red"}}>
          © {new Date().getFullYear()} Secure Wipe Utility. All rights reserved.
        </small>
      </footer>
    </div>
  );
}
