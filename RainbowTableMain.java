public class RainbowTableMain {

	private static int NUM_CHAINS = 40000;
	private static int CHAIN_LENGTH = 200;
	
	public RainbowTableMain() {
		this(NUM_CHAINS, CHAIN_LENGTH);
	}
	
	public RainbowTableMain(int numChains, int chainLength) {
		RainbowTable rt = new RainbowTable(numChains, chainLength);
	}
	
	public static void main(String[] args) {
		if(args.length == 2) {
			new RainbowTableMain(Integer.parseInt(args[0]), Integer.parseInt(args[1]));
		}
		else { 
			new RainbowTableMain();
		}
	}
}
