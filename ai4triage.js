const fs = require('fs');
const csv = require('csv-parser');
const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'ai4cyber-local',
  brokers: ['localhost:9093'], // 👈 No TLS
});

const producer = kafka.producer();

const labelToDescription = {
  'DoS GoldenEye': 'Denial of Service attack using GoldenEye tool.',
  'FTP-Patator': 'Brute force attack on FTP using Patator tool.',
  'SSH-Patator': 'Brute force attack on SSH using Patator tool.',
  'PortScan': 'Network port scanning activity.',
  'DDoS': 'Distributed Denial of Service attack.',
  'Web Attack – Brute Force': 'Brute force attack on web application.',
  'Web Attack – XSS': 'Cross-site scripting attack on web application.',
  'Web Attack – Sql Injection': 'SQL injection attack on web application.',
  'Bot': 'Botnet-related malicious traffic.',
  'Infiltration': 'Infiltration of internal systems.',
  'Heartbleed': 'Heartbleed vulnerability exploitation.',
  'Malicious': 'Unspecified malicious activity.',
};

const labelToTTPs = {
  'DoS GoldenEye': ['T1499'],
  'FTP-Patator': ['T1110.001'],
  'SSH-Patator': ['T1110.001'],
  'PortScan': ['T1595.001'],
  'DDoS': ['T1499.001'],
  'Web Attack – Brute Force': ['T1110'],
  'Web Attack – XSS': ['T1059.007'],
  'Web Attack – Sql Injection': ['T1190'],
  'Bot': ['T1583.006'],
  'Infiltration': ['T1203'],
  'Heartbleed': ['T1210'],
  'Malicious': ['T1583'],
};

if (process.argv.length < 3) {
  console.error("❌ Usage: node csvToStix.js <csvFile>");
  process.exit(1);
}

const csvFile = process.argv[2];

(async () => {
  await producer.connect();

  fs.createReadStream(csvFile)
    .pipe(csv())
    .on('data', async (row) => {
      const features = { ...row };
      const label = features.attack_label;
      delete features.attack_label;

      const now = new Date();
      const nowISO = now.toISOString();
      const timestampSuffix = nowISO.replace(/T|:|\..+$/g, "-");

      const srcIP = features["Src IP"];
      const dstIP = features["Dst IP"];
      const dstPort = features["Dst Port"];
      const srcPort = features["Src Port"];
      const proto = features["Protocol"];

      const flowId = `${srcIP}-${dstIP}-${dstPort}-${srcPort}-${proto}-${timestampSuffix}`;
      features["Flow ID"] = flowId;
      features["Timestamp"] = nowISO;

      const description = labelToDescription[label] || `Mapped TTPs for label ${label}`;
      const ttps = labelToTTPs[label] || ['T1583'];

      const alert = {
        flow_features: features,
        attack_type: label || "Unknown",
        attack_description: description,
        ttps: ttps,
        confidence: 1.0,
      };

      try {
        await producer.send({
          topic: 'ai4triage.sc2.2.stix_alerts',
          messages: [{ value: JSON.stringify(alert) }],
        });

        console.log(`[${nowISO}] ✅ Sent alert for label '${label}'`);
      } catch (err) {
        console.error(`❌ Kafka send failed for label '${label}':`, err);
      }
    })
    .on('end', async () => {
      await producer.disconnect();
      console.log(`✅ Finished reading file: ${csvFile}`);
    })
    .on('error', async (err) => {
      console.error("❌ CSV parsing error:", err);
      await producer.disconnect();
    });
})();
