import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

class SyncedCounter {
    private int counter = 0;

    public int getCounter() {
        return counter;
    }

    public synchronized void increment() {
        counter = counter + 1;
    }

}

public class MultiThreadMain {
    public static void main(String[] args) throws InterruptedException {
        ExecutorService executorService = Executors.newFixedThreadPool(8);

        SyncedCounter syncedCounter = new SyncedCounter();

        for(int i = 0; i < 10000; i++) {
            executorService.submit(() -> syncedCounter.increment());
        }

        executorService.shutdown();
        executorService.awaitTermination(30, TimeUnit.SECONDS);

        System.out.println("Final Count is: " + syncedCounter.getCounter());
    }
}
