const { Kafka } = require('kafkajs');

// Kafka config (local broker on port 9093 with no auth)
const kafka = new Kafka({
  clientId: 'stix-alert-consumer',
  brokers: ['localhost:9093'],
});

const topic = 'ai4triage.sc2.2.stix_alerts';
const groupId = 'stix-alert-test-group';

const consumer = kafka.consumer({ groupId });

const run = async () => {
  await consumer.connect();
  await consumer.subscribe({ topic, fromBeginning: true });

  console.log(`📥 Subscribed to topic: ${topic}`);

  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      const value = message.value.toString();
      console.log(`\n--- Received Message ---`);
      console.log(`Partition: ${partition}`);
      console.log(`Offset: ${message.offset}`);
      console.log(`Message:\n${value}`);
    },
  });
};

run().catch((error) => {
  console.error('❌ Error in consumer:', error);
  process.exit(1);
});

