const queue = [];

function enqueue(task) {
  queue.push(task);
}

let queueRunning = false;

const interval = setInterval(async () => {
  if (!queueRunning) {
    queueRunning = true;
    const task = queue.shift();
    if (task) {
      try {
        await task();
      } catch (e) {
        console.error(e);
      }
    }

    queueRunning = false;
  }
}, 1000);

module.exports = {
  enqueue
};
