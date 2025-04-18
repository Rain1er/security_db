package com.rain.controller;

import org.springframework.web.bind.annotation.*;

/**
 *
 * curl http://127.0.0.1:8080/bypass/raindrop/index.html
 *
 * 
 */
@RestController
public class BypassTestController {

    /**
     * @return
     */
    @RequestMapping(value = "/bypass/{id}/index", method = RequestMethod.GET)
    public String bypass(@PathVariable("id") String id) {
        return "bypass -> " + id;
    }

}
