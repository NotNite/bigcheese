const queue = [];

function enqueue(task, fail) {
  queue.push([task, fail]);
}

let queueRunning = false;

const interval = setInterval(async () => {
  if (!queueRunning) {
    queueRunning = true;
    const potentialTask = queue.shift();
    if (potentialTask) {
      const [task, fail] = potentialTask;
      try {
        await task();
      } catch (e) {
        console.error(e);
        try {
          await fail();
        } catch (e) {
          console.error(e);
        }
      }
    }

    queueRunning = false;
  }
}, 1000);

module.exports = {
  enqueue
};
