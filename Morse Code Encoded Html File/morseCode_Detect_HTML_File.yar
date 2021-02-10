rule morseCode_Detect_HTML_File
{
    meta:
        author = "Bartu Kilic <kilicbartu@gmail.com>"
        reference = "http://bartukilic.com.tr/"
        description = "Rule to detect the morse code encoded strings."
    strings:
        $filetype = ".htm" nocase
        //$morse_a = ".-"  
        $morse_b = "-..."
        $morse_c = "-.-."
        $morse_d = "-.." 
        //$morse_e = "."   
        $morse_f = "..-."
        $morse_g = "--." 
        //$morse_h = "...."
        //$morse_i = ".."  
        $morse_j = ".---"
        $morse_k = "-.-" 
        $morse_l = ".-.."
        //$morse_m = "--"  
        //$morse_n = "-."  
        $morse_o = "---" 
        $morse_p = ".--."
        $morse_q = "--.-"
        $morse_r = ".-." 
        //$morse_s = "..." 
        //$morse_t = "-"   
        //$morse_u = "..-" 
        //$morse_v = "...-"
        $morse_w = ".--" 
        $morse_x = "-..-"
        $morse_y = "-.--"
        $morse_z = "--.."
        $morse_1 = ".----"
        $morse_2 = "..---"
        $morse_3 = "...--"
        $morse_4 = "....-"
        $morse_5 = "....."
        $morse_6 = "-...."
        $morse_7 = "--..."
        $morse_8 = "---.."
        $morse_9 = "----."
        $morse_0 = "-----"
    condition:
        filesize < 2MB
        $filetype and any of ($morse_*)
}
