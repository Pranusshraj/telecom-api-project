const fs = require('fs');

const generateData = () => {
  const subscribers = [];
  const plans = ['Basic-Voice', 'Data-Max-5G', 'Unlimited-Pro', 'Family-Share'];
  const statuses = ['Active', 'Suspended', 'Pending', 'Expired'];

  for (let i = 1; i <= 100; i++) {
    subscribers.push({
      id: i.toString(),
      phoneNumber: `98840${10000 + i}`,
      name: `Subscriber ${i}`,
      plan: plans[Math.floor(Math.random() * plans.length)],
      status: statuses[Math.floor(Math.random() * statuses.length)],
      dataBalanceGB: parseFloat((Math.random() * 50).toFixed(2)),
      lastRechargeDate: new Date(Date.now() - Math.floor(Math.random() * 1000000000)).toISOString().split('T')[0]
    });
  }

  const db = { subscribers, transactions: [] };
  fs.writeFileSync('db.json', JSON.stringify(db, null, 2));
  console.log("✅ db.json generated with 100 subscribers.");
};

generateData();