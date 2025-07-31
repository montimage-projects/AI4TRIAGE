const fs = require('fs');
const csv = require('csv-parser');
const { Kafka } = require('kafkajs');

// Kafka config
const kafka = new Kafka({
  clientId: 'ai4cyber-local',
  brokers: ['localhost:9093'], // No TLS
});

const producer = kafka.producer();

// Mapping predicted labels to attack descriptions
const labelToFinanceAttack = {
  0: 'Others',
  1: 'Finance – HTTP Data Exfiltration',
  2: 'Data exfiltration HTTP Files v2',
  3: 'Finance - Exchange data exfiltration using basic HTTP Request v2',
  4: 'Finance - HTTP Data exfiltration (XOR Encrypted) v2',
  5: 'Finance - Data Exfiltration - HTTP Windows files v2',
  6: 'Finance - Data Exfiltration - Ransomware attack',
  7: 'Finance - Ransomware Attack (CymRansom)',
  8: 'Finance - Ransomware Attack (Mimic Ransom)',
  9: 'Finance - Data exfiltration over DNS',
  10: 'Finance - Data exfiltration using PSFTP',
  11: 'Finance - Data exfiltration + Ransomware attack v2',
};

const labelToTTPs = {
  0: ['T1583'],
  1: ['T1041', 'T1071.001'],
  2: ['T1041', 'T1071.001'],
  3: ['T1041', 'T1071.001'],
  4: ['T1041', 'T1071.001'],
  5: ['T1041', 'T1071.001'],
  6: ['T1486', 'T1041'],
  7: ['T1486', 'T1059.003'],
  8: ['T1486', 'T1059.003'],
  9: ['T1041', 'T1071.004'],
  10: ['T1041', 'T1105'],
  11: ['T1486', 'T1041'],
};

const labelToMitigations = {
  0: ['Network segmentation', 'User awareness training'],
  1: ['Inspect HTTP traffic', 'Apply DLP controls'],
  2: ['Inspect HTTP traffic', 'Apply DLP controls'],
  3: ['Monitor web requests', 'Limit external exchange access'],
  4: ['Monitor for encrypted exfiltration patterns'],
  5: ['Block unauthorized file transfers'],
  6: ['Backups & segmentation', 'Disable macros'],
  7: ['Endpoint protection', 'Patch vulnerabilities'],
  8: ['Endpoint protection', 'Patch vulnerabilities'],
  9: ['DNS tunneling detection', 'Limit external DNS'],
  10: ['Control remote file transfer tools'],
  11: ['Layered ransomware defense', 'Exfiltration monitoring'],
};

// Handle missing values
function safe(value) {
  return value && value !== 'undefined' ? value : 'UND';
}

// Entry point
if (process.argv.length < 3) {
  console.error("❌ Usage: node csvToStix.js <csvFile>");
  process.exit(1);
}

const csvFile = process.argv[2];
const logFile = 'ai4triage_stix.json';

(async () => {
  await producer.connect();
  const writeStream = fs.createWriteStream(logFile, { flags: 'a' });
  const processingPromises = [];

  fs.createReadStream(csvFile)
    .pipe(csv())
    .on('data', (row) => {
      const promise = (async () => {
        try {
          const features = { ...row };
          const label = parseInt(features.predicted_label);
          delete features.predicted_label;

          const now = new Date();
          const nowISO = now.toISOString();
          const timestampSuffix = nowISO.replace(/T|:|\..+$/g, "-");

          const srcIP = safe(features["Src IP"]);
          const dstIP = safe(features["Dst IP"]);
          const dstPort = safe(features["Dst Port"]);
          const srcPort = safe(features["Src Port"]);
          const proto = safe(features["Protocol"]);

          const flowId = `${srcIP}-${dstIP}-${dstPort}-${srcPort}-${proto}-${timestampSuffix}`;
          features["Flow ID"] = flowId;
          features["Timestamp"] = nowISO;

          const attackType = labelToFinanceAttack[label] || "Unknown";
          const ttps = labelToTTPs[label] || [];
          const mitigations = labelToMitigations[label] || [];

          const alert = {
            flow_features: features,
            attack_type: attackType,
            attack_description: attackType,
            ttps: ttps,
            mitigations: mitigations,
            confidence: 1.0,
          };

          const alertStr = JSON.stringify(alert);

          // Send to Kafka
          await producer.send({
            topic: 'ai4triage.sc2.2.stix_alerts',
            messages: [{ value: alertStr }],
          });

          // Append to file (synchronously ensures flush)
          writeStream.write(alertStr + '\n');

          console.log(`[${nowISO}] ✅ Alert sent and logged for label '${label}'`);
        } catch (err) {
          console.error("❌ Processing error:", err);
        }
      })();

      processingPromises.push(promise);
    })
    .on('end', async () => {
      try {
        await Promise.all(processingPromises);
        writeStream.end();
        await producer.disconnect();
        console.log(`✅ Finished processing file: ${csvFile}`);
        process.exit(0);
      } catch (err) {
        console.error("❌ Error in cleanup:", err);
        process.exit(1);
      }
    })
    .on('error', async (err) => {
      console.error("❌ CSV reading error:", err);
      writeStream.end();
      await producer.disconnect();
      process.exit(1);
    });
})();
