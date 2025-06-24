<?php

if (empty($errors)) {
    header('Content-Type: text/xml');
    echo $metadata;
    exit();
} else {
    echo '<div class="row text-left">
            <div class="col-lg-9 col-sm-9  ">
                <b>Invalid SP metadata:</b> '.implode(', ', $errors).
           '</div>
          </div>';
}
