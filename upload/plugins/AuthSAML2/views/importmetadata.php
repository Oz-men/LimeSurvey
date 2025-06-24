<div class="container">
<?php

    $modes = array(
        "default" => gT("Save as Default IdP"),
        "extra" => gT("Save as Extra IdP")
    );

    echo CHtml::beginForm('', 'post', []);
?>
    <div class="row">
        <div class="col-xs-12">
            <div class="pagetitle h3"><?php eT("Import SAML Metadata"); ?></div>
            <div class="container-fluid">

                <div class="row">
                    <div class="col-sm-12 col-md-12">
<?php
if (!empty($error)) {
    echo '<div class="form-group has-error">';
} else {
    echo '<div class="form-group">';
}
                                echo CHtml::label(gT("SAML Metadata XML:"), 'lang', array('class'=>" control-label"));

                                echo CHtml::textArea('metadataxml', "", array('class'=>'form-control', 'rows'=> 28, 'cols' => 10)); ?>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-sm-12 col-md-12">
                        <div class="form-group">
                            <?php echo CHtml::label(gT("Import Mode:"), 'lang', array('class'=>" control-label")); ?>
                            <div class="">
                                <?php echo CHtml::dropDownList('mode', "", $modes, array('class'=>'form-control')); ?>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-sm-12 col-md-12">
                        <div class="form-group">
                            <?php echo CHtml::hiddenField('action', 'importsamlmetadata'); ?>
                            <?php echo CHtml::submitButton(gT("Save metadata", 'unescaped'), array('name' => "save", 'class' => 'btn btn-success')); ?>
                            <?php echo CHtml::submitButton(gT("Save metadata and continue importing", 'unescaped'), array('name' => "saveandcontinue", 'class' => 'btn btn-default')); ?>
                            <?php echo CHtml::submitButton(gT("Close", 'unescaped'), array('name' => "close", 'class' => "btn btn-danger")); ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

<?php
    echo CHtml::endForm();
?>
</div>