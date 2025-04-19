
public class Calc {
  static {
    try {
      System.out.println("run Calc...");
      Runtime.getRuntime().exec("open -a Calculator.app");
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }
}
