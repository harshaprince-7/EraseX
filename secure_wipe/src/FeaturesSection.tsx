import "./App.css";

export default function FeaturesSection() {
  const features = [
    {
      title: "Drive Wiping",
      description: "Erase HDDs and SSDs with NIST-certified secure wipe methods.",
      icon: "/icons/hdd.png",
    },
    {
      title: "Cross-Platform Support",
      description: "Works on Windows, Linux & Android with a unified solution.",
      icon: "/icons/platforms.png",
    },
    {
      title: "Remote Wiping",
      description: "Wipe multiple systems remotely from a centralized console.",
      icon: "/icons/remote.png",
    },
    {
      title: "Mobile Device Wiping",
      description: "Erase iOS & Android devices with tamper-proof proof reports.",
      icon: "/icons/mobile.png",
    },
    {
      title: "Audit-Ready Certificates",
      description: "Each wipe generates a verifiable certificate for compliance.Open Audit Transparency",
      icon: "/icons/certificate.png",
    },
    {
      title: "File & Folder Erasure",
      description: "Delete specific sensitive files without affecting the system.",
      icon: "/icons/file.png",
    },
  ];

  return (
    <section className="features" id="solutions">
      <h2>Secure Data Erasure Solutions for Every Need</h2>
      <p>
        TraceZero empowers organizations and individuals with certified, scalable, and simple data wiping tools.
      </p>

      <div className="features-grid">
        {features.map((f, i) => (
          <div key={i} className="feature-card">
            <img src={f.icon} alt={f.title} />
            <div className="feature-text">
            <h3>{f.title}</h3>
            <p>{f.description}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
