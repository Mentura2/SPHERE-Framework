<?php

namespace SPHERE\Application\Education\ClassRegister\Instruction;

use SPHERE\Application\Api\Education\ClassRegister\ApiInstructionItem;
use SPHERE\Application\Api\Education\ClassRegister\ApiInstructionSetting;
use SPHERE\Application\Education\ClassRegister\Digital\Digital;
use SPHERE\Application\Education\ClassRegister\Instruction\Service\Entity\TblInstruction;
use SPHERE\Application\Education\Graduation\Gradebook\MinimumGradeCount\SelectBoxItem;
use SPHERE\Application\Education\Lesson\Division\Division;
use SPHERE\Application\Education\Lesson\Division\Service\Entity\TblDivision;
use SPHERE\Application\Education\Lesson\Division\Service\Entity\TblDivisionSubject;
use SPHERE\Application\Education\Lesson\Term\Term;
use SPHERE\Application\Education\School\Type\Type;
use SPHERE\Application\People\Group\Group;
use SPHERE\Application\People\Group\Service\Entity\TblGroup;
use SPHERE\Common\Frontend\Form\Repository\Field\CheckBox;
use SPHERE\Common\Frontend\Form\Repository\Field\DatePicker;
use SPHERE\Common\Frontend\Form\Repository\Field\SelectBox;
use SPHERE\Common\Frontend\Form\Repository\Field\TextArea;
use SPHERE\Common\Frontend\Form\Repository\Field\TextField;
use SPHERE\Common\Frontend\Form\Structure\Form;
use SPHERE\Common\Frontend\Form\Structure\FormColumn;
use SPHERE\Common\Frontend\Form\Structure\FormGroup;
use SPHERE\Common\Frontend\Form\Structure\FormRow;
use SPHERE\Common\Frontend\Icon\Repository\Check;
use SPHERE\Common\Frontend\Icon\Repository\ChevronLeft;
use SPHERE\Common\Frontend\Icon\Repository\CommodityItem;
use SPHERE\Common\Frontend\Icon\Repository\Disable;
use SPHERE\Common\Frontend\Icon\Repository\Edit;
use SPHERE\Common\Frontend\Icon\Repository\Exclamation;
use SPHERE\Common\Frontend\Icon\Repository\Filter;
use SPHERE\Common\Frontend\Icon\Repository\MinusSign;
use SPHERE\Common\Frontend\Icon\Repository\Plus;
use SPHERE\Common\Frontend\Icon\Repository\PlusSign;
use SPHERE\Common\Frontend\Icon\Repository\Remove;
use SPHERE\Common\Frontend\Icon\Repository\Save;
use SPHERE\Common\Frontend\IFrontendInterface;
use SPHERE\Common\Frontend\Layout\Repository\Container;
use SPHERE\Common\Frontend\Layout\Repository\Panel;
use SPHERE\Common\Frontend\Layout\Repository\PullRight;
use SPHERE\Common\Frontend\Layout\Repository\Title;
use SPHERE\Common\Frontend\Layout\Structure\Layout;
use SPHERE\Common\Frontend\Layout\Structure\LayoutColumn;
use SPHERE\Common\Frontend\Layout\Structure\LayoutGroup;
use SPHERE\Common\Frontend\Layout\Structure\LayoutRow;
use SPHERE\Common\Frontend\Link\Repository\Primary;
use SPHERE\Common\Frontend\Link\Repository\Standard;
use SPHERE\Common\Frontend\Message\Repository\Danger;
use SPHERE\Common\Frontend\Table\Structure\TableData;
use SPHERE\Common\Frontend\Text\Repository\Small;
use SPHERE\Common\Frontend\Text\Repository\Success;
use SPHERE\Common\Frontend\Text\Repository\ToolTip;
use SPHERE\Common\Frontend\Text\Repository\Warning;
use SPHERE\Common\Window\Redirect;
use SPHERE\Common\Window\Stage;
use SPHERE\System\Extension\Extension;
use SPHERE\System\Extension\Repository\Sorter\StringNaturalOrderSorter;

class Frontend extends Extension implements IFrontendInterface
{
    /**
     * @return Stage
     */
    public function frontendInstructionSetting(): Stage
    {
        $stage = new Stage('Einstellungen', 'Belehrungen');
        $stage->setContent(ApiInstructionSetting::receiverModal()
            . (new Primary(
                new Plus() . ' Belehrung hinzufügen',
                ApiInstructionSetting::getEndpoint()
            ))->ajaxPipelineOnClick(ApiInstructionSetting::pipelineOpenCreateInstructionModal())
            . new Container('&nbsp;')
            . ApiInstructionSetting::receiverBlock($this->loadInstructionSettingTable(), 'InstructionContent')
        );

        return  $stage;
    }

    /**
     * @return string
     */
    public function loadInstructionSettingTable(): string
    {
        $dataList = array();
        if (($tblInstructionList = Instruction::useService()->getInstructionAll(false))) {
            foreach ($tblInstructionList as $tblInstruction) {
                $hasInstructionItems = Instruction::useService()->getInstructionItemAllByInstruction($tblInstruction, null, null, null);
                $dataList[] = array(
                    'Subject' => $tblInstruction->getSubject(),
                    'Content' => $tblInstruction->getContent(),
                    'Status' => $tblInstruction->getIsActive()
                        ? new Success(new PlusSign().' aktiv')
                        : new Warning(new MinusSign() . ' inaktiv'),
                    'Option' =>
                        (new Standard(
                            '',
                            ApiInstructionSetting::getEndpoint(),
                            new Edit(),
                            array(),
                            'Bearbeiten'
                        ))->ajaxPipelineOnClick(ApiInstructionSetting::pipelineOpenEditInstructionModal($tblInstruction->getId()))
                        . (new Standard(
                            '',
                            ApiInstructionSetting::getEndpoint(),
                            $tblInstruction->getIsActive() ? new MinusSign() : new PlusSign(),
                            array(),
                            $tblInstruction->getIsActive() ? 'Deaktivieren' : 'Aktivieren'
                        ))->ajaxPipelineOnClick(ApiInstructionSetting::pipelineActivateInstructionSave($tblInstruction->getId()))
                        . (!$hasInstructionItems
                            ? (new Standard(
                                '',
                                ApiInstructionSetting::getEndpoint(),
                                new Remove(),
                                array(),
                                'Löschen'
                            ))->ajaxPipelineOnClick(ApiInstructionSetting::pipelineOpenDeleteInstructionModal($tblInstruction->getId()))
                            : '')
                );
            }
        }

        return new TableData(
            $dataList,
            null,
            array(
                'Subject' => 'Thema',
                'Content' => 'Inhalt',
                'Status' => 'Status',
                'Option' => ''
            ),
            array(
                'order' => array(
                    array(0, 'asc')
                ),
                'columnDefs' => array(
                    array('width' => '60px', 'targets' => -2),
                    array('width' => '100px', 'targets' => -1),
                ),
                'responsive' => false
            )
        );
    }

    /**
     * @param null $InstructionId
     * @param bool $setPost
     *
     * @return Form
     */
    public function formInstruction($InstructionId = null, bool $setPost = false): Form
    {
        // beim Checken der Input-Felder darf der Post nicht gesetzt werden
        if ($setPost && $InstructionId
            && ($tblInstruction = Instruction::useService()->getInstructionById($InstructionId))
        ) {
            $Global = $this->getGlobal();
            $Global->POST['Data']['Subject'] = $tblInstruction->getSubject();
            $Global->POST['Data']['Content'] = $tblInstruction->getContent();
            $Global->savePost();
        }

        if ($InstructionId) {
            $saveButton = (new Primary('Speichern', ApiInstructionSetting::getEndpoint(), new Save()))
                ->ajaxPipelineOnClick(ApiInstructionSetting::pipelineEditInstructionSave($InstructionId));
        } else {
            $saveButton = (new Primary('Speichern', ApiInstructionSetting::getEndpoint(), new Save()))
                ->ajaxPipelineOnClick(ApiInstructionSetting::pipelineCreateInstructionSave());
        }
        $buttonList[] = $saveButton;

        return (new Form(
            new FormGroup(array(
                new FormRow(array(
                    new FormColumn(
                        (new TextField('Data[Subject]', 'Thema', 'Thema', new Edit()))->setRequired()
                    ),
                )),
                new FormRow(array(
                    new FormColumn(
                        new TextArea('Data[Content]', 'Inhalt', 'Inhalt', new Edit())
                    ),
                )),
                new FormRow(array(
                    new FormColumn(
                        $buttonList
                    )
                )),
            ))
        ))->disableSubmitAction();
    }

    /**
     * @param null $DivisionId
     * @param null $GroupId
     * @param null $DivisionSubjectId
     * @param string $BasicRoute
     *
     * @return Stage|string
     */
    public function frontendInstruction(
        $DivisionId = null,
        $GroupId = null,
        $DivisionSubjectId = null,
        string $BasicRoute = '/Education/ClassRegister/Digital/Teacher'
    ) {
        $stage = new Stage('Digitales Klassenbuch', 'Belehrungen');

        $tblYear = null;
        $tblDivision = Division::useService()->getDivisionById($DivisionId);
        $tblGroup = Group::useService()->getGroupById($GroupId);
        if (($tblDivisionSubject = Division::useService()->getDivisionSubjectById($DivisionSubjectId))) {
            if ($GroupId) {
                $stage->addButton(new Standard(
                    'Zurück', '/Education/ClassRegister/Digital/SelectCourse', new ChevronLeft(), array(
                        'GroupId' => $GroupId,
                        'BasicRoute' => $BasicRoute
                    )
                ));
            } else {
                $stage->addButton(new Standard(
                    'Zurück', '/Education/ClassRegister/Digital/SelectCourse', new ChevronLeft(), array(
                        'DivisionId' => $DivisionId,
                        'BasicRoute' => $BasicRoute
                    )
                ));
            }
        } else {
            $stage->addButton(new Standard(
                'Zurück', $BasicRoute, new ChevronLeft(), array('IsGroup' => $GroupId)
            ));
        }

        if ($tblDivision || $tblGroup || $tblDivisionSubject) {
            $stage->setContent(
                new Layout(array(
                    new LayoutGroup(array(
                        Digital::useService()->getHeadLayoutRow(
                            $tblDivision ?: null, $tblGroup ?: null, $tblYear, $tblDivisionSubject ?: null
                        ),
                        $tblDivisionSubject
                            ? Digital::useService()->getHeadButtonListLayoutRowForDivisionSubject($tblDivisionSubject, $DivisionId, $GroupId,
                                '/Education/ClassRegister/Digital/Instruction', $BasicRoute)
                            : Digital::useService()->getHeadButtonListLayoutRow($tblDivision ?: null, $tblGroup ?: null,
                                '/Education/ClassRegister/Digital/Instruction', $BasicRoute)

                    )),
                    new LayoutGroup(new LayoutRow(new LayoutColumn(
                        ApiInstructionItem::receiverModal()
                        . ApiInstructionItem::receiverBlock(
                            $this->loadInstructionItemTable(
                                $tblDivision && !$tblDivisionSubject ? $tblDivision : null,
                                $tblGroup && !$tblDivisionSubject ? $tblGroup : null,
                                $tblDivisionSubject ?: null
                            ),
                            'InstructionItemContent'
                        )
                    )), new Title(new CommodityItem() . ' Belehrungen'))
                ))
            );
        } else {
            return new Danger('Klasse oder Gruppe nicht gefunden', new Exclamation())
                . new Redirect($BasicRoute, Redirect::TIMEOUT_ERROR);
        }

        return $stage;
    }

    /**
     * @param TblDivision|null $tblDivision
     * @param TblGroup|null $tblGroup
     * @param TblDivisionSubject|null $tblDivisionSubject
     *
     * @return string
     */
    public function loadInstructionItemTable(?TblDivision $tblDivision, ?TblGroup $tblGroup, ?TblDivisionSubject $tblDivisionSubject): string
    {
        $dataList = array();
        if (($tblInstructionList = Instruction::useService()->getInstructionAll())) {
            foreach ($tblInstructionList as $tblInstruction) {
                $subject = $tblInstruction->getSubject();
                $content = $tblInstruction->getContent();
                $count = 0;
                $sublist = array();
                if (($tblInstructionItemList = Instruction::useService()->getInstructionItemAllByInstruction($tblInstruction, $tblDivision, $tblGroup, $tblDivisionSubject))) {
                    foreach ($tblInstructionItemList as $tblInstructionItem) {
                        if ($tblInstructionItem->getIsMain()) {
                            $content = $tblInstructionItem->getContent();
                            if ($tblInstructionItem->getSubject()) {
                                $subject = $tblInstructionItem->getSubject();
                            }
                            $index = 0;
                        } else {
                            $index = ++$count;
                        }
                        $missingStudents = Instruction::useService()->getMissingPersonNameListByInstructionItem($tblInstructionItem);

                        $pretext = ($count == 0 ? 'Belehrung' : $count . '. Nachbelehrung')
                            . ' ' . $tblInstructionItem->getDate();
                        $sublist[$index] = $pretext
                            . ($missingStudents ? ' - ' . new ToolTip(new Warning(count($missingStudents) . ' fehlende'
                                    . (count($missingStudents) == 1 ? 'r' : '') . ' Schüler'), implode(' - ', $missingStudents)) : '')
                            . ' - '. $tblInstructionItem->getTeacherString()
                            . new PullRight((new Standard('', ApiInstructionItem::getEndpoint(), new Edit(), array(), $pretext .  ' bearbeiten'))
                                ->ajaxPipelineOnClick(ApiInstructionItem::pipelineOpenEditInstructionItemModal(
                                    $tblInstructionItem->getId()
                                )));
                    }

                    if (($missingPersonTotal = Instruction::useService()->getMissingStudentsByInstruction($tblInstruction, $tblDivision, $tblGroup, $tblDivisionSubject))) {
                        $sublist[] = (new Standard('', ApiInstructionItem::getEndpoint(), new Plus(), array(), 'Neue Nachbelehrung hinzufügen'))
                            ->ajaxPipelineOnClick(ApiInstructionItem::pipelineOpenCreateInstructionItemModal(
                                $tblDivision ? $tblDivision->getId() : null, $tblGroup ? $tblGroup->getId() : null,
                                $tblDivisionSubject ? $tblDivisionSubject->getId() : null, $tblInstruction->getId()
                            ));
                        $panel = new Panel('Belehrung teilweise durchgeführt', $sublist, Panel::PANEL_TYPE_WARNING)
                            . new Panel('Fehlende Schüler', $missingPersonTotal, Panel::PANEL_TYPE_WARNING);
                    } else {
                        $panel = new Panel(new Check() . ' Belehrung vollständig durchgeführt', $sublist, Panel::PANEL_TYPE_SUCCESS);
                    }
                } else {
                    $sublist[] = (new Standard('', ApiInstructionItem::getEndpoint(), new Plus(), array(), 'Neue Belehrung hinzufügen'))
                        ->ajaxPipelineOnClick(ApiInstructionItem::pipelineOpenCreateInstructionItemModal(
                            $tblDivision ? $tblDivision->getId() : null, $tblGroup ? $tblGroup->getId() : null,
                            $tblDivisionSubject ? $tblDivisionSubject->getId() : null, $tblInstruction->getId()
                        ));
                    $panel = new Panel(new Exclamation() . ' Keine Belehrung durchgeführt', $sublist, Panel::PANEL_TYPE_DANGER);
                }

                $dataList[] = array(
                    'Subject' => $subject,
                    'Content' => $content,
                    'Transactions' => $panel
                );
            }
        }

        return new TableData(
            $dataList,
            null,
            array(
                'Subject' => 'Thema',
                'Content' => 'Inhalt',
                'Transactions' => 'Durchführung'
            ),
            array(
                'order' => array(
                    array(0, 'asc')
                ),
//                'columnDefs' => array(
//                    array('width' => '60px', 'targets' => -1),
//                ),
                'responsive' => false
            )
        );
    }

    /**
     * @param TblDivision|null $tblDivision
     * @param TblGroup|null $tblGroup
     * @param TblDivisionSubject|null $tblDivisionSubject
     * @param TblInstruction $tblInstruction
     * @param null $InstructionItemId
     * @param bool $setPost
     *
     * @return Form
     */
    public function formInstructionItem(?TblDivision $tblDivision, ?TblGroup $tblGroup, ?TblDivisionSubject $tblDivisionSubject, TblInstruction $tblInstruction,
        $InstructionItemId = null, bool $setPost = false): Form
    {
        $tblMainInstructionItem = Instruction::useService()->getMainInstructionItemBy($tblInstruction, $tblDivision, $tblGroup, $tblDivisionSubject);

        $tblInstructionItem = false;
        if ($InstructionItemId) {
            $tblInstructionItem = Instruction::useService()->getInstructionItemById($InstructionItemId);
        }
        $Global = $this->getGlobal();
        // beim Checken der Input-Felder darf der Post nicht gesetzt werden
        if ($setPost && $tblInstructionItem) {
            $Global->POST['Data']['Date'] = $tblInstructionItem->getDate();
            if ($tblInstructionItem->getIsMain()) {
                $Global->POST['Data']['Content'] = $tblInstructionItem->getContent();
            }
            if (($tblInstructionItemStudents = Instruction::useService()->getMissingStudentsByInstructionItem($tblInstructionItem))) {
                foreach ($tblInstructionItemStudents as $tblInstructionItemStudent) {
                    if (($tblPersonItem = $tblInstructionItemStudent->getServiceTblPerson())) {
                        $Global->POST['Data']['Students'][$tblPersonItem->getId()] = 1;
                        $setStudents[$tblPersonItem->getId()] = $tblPersonItem;
                    }
                }
            }
        } elseif (!$InstructionItemId && !$tblMainInstructionItem && $tblInstruction->getContent()) {
            $Global->POST['Data']['Content'] = $tblInstruction->getContent();
        }

        $Global->savePost();

        $formRows[] = new FormRow(new FormColumn((new DatePicker('Data[Date]', 'Datum', 'Datum', new Edit()))->setRequired()));

        // Thema hinzufügen und bearbeiten für Hauptbelehrung und nicht bei Nachbelehrung
        if (!$tblMainInstructionItem || ($tblInstructionItem && $tblInstructionItem->getIsMain())) {
            $formRows[] = new FormRow(new FormColumn((new TextArea('Data[Content]', 'Inhalt', 'Inhalt', new Edit()))->setRequired()));
        }

        $columns = array();
        if ($tblDivisionSubject) {
            $tblPersonList = Division::useService()->getStudentByDivisionSubject($tblDivisionSubject);
        } elseif ($tblDivision) {
            $tblPersonList = Division::useService()->getStudentAllByDivision($tblDivision);
        } elseif ($tblGroup) {
            if (($tblPersonList = Group::useService()->getPersonAllByGroup($tblGroup))) {
                $tblPersonList = $this->getSorter($tblPersonList)->sortObjectBy('LastFirstName');
            }

        } else {
            $tblPersonList = false;
        }
        if ($tblPersonList) {
            $missingPersonTotal = Instruction::useService()->getMissingStudentsByInstruction($tblInstruction, $tblDivision, $tblGroup, $tblDivisionSubject);
            foreach ($tblPersonList as $tblPerson) {
                // bei Nachbelehrung nur die fehlenden Schüler zur Auswahl anzeigen
                if (!$missingPersonTotal || $InstructionItemId || isset($missingPersonTotal[$tblPerson->getId()])) {
                    $columns[$tblPerson->getId()] = new FormColumn(new CheckBox('Data[Students][' . $tblPerson->getId() . ']',
                        $tblPerson->getLastFirstName(), 1), 4);
                }
            }
        }

        if ($InstructionItemId) {
            $saveButton = (new Primary('Speichern', ApiInstructionItem::getEndpoint(), new Save()))
                ->ajaxPipelineOnClick(ApiInstructionItem::pipelineEditInstructionItemSave($InstructionItemId));
        } else {
            $saveButton = (new Primary('Speichern', ApiInstructionItem::getEndpoint(), new Save()))
                ->ajaxPipelineOnClick(ApiInstructionItem::pipelineCreateInstructionItemSave(
                    $tblDivision ? $tblDivision->getId() : null,
                    $tblGroup ? $tblGroup->getId() : null,
                    $tblDivisionSubject ? $tblDivisionSubject->getId() : null,
                    $tblInstruction->getId()
                ));
        }
        $buttonList[] = $saveButton;

        // Belehrung löschen
        if ($InstructionItemId && $tblInstructionItem
            // Hauptbelehrung erst löschen wenn alle Nachbelehrungen gelöscht wurden
            && (!$tblInstructionItem->getIsMain()
                || count(Instruction::useService()->getInstructionItemAllByInstruction($tblInstruction, $tblDivision, $tblGroup, $tblDivisionSubject)) == 1)
        ) {
            $buttonList[] = (new \SPHERE\Common\Frontend\Link\Repository\Danger(
                'Löschen',
                ApiInstructionItem::getEndpoint(),
                new Remove(),
                array(),
                false
            ))->ajaxPipelineOnClick(ApiInstructionItem::pipelineOpenDeleteInstructionItemModal($InstructionItemId));
        }

        return (new Form(array(
            new FormGroup(
                $formRows
            ),
            new FormGroup(array(
                new FormRow(
                    $columns,
                ),
                new FormRow(array(
                    new FormColumn(
                        $buttonList
                    )
                )),
            ), new \SPHERE\Common\Frontend\Form\Repository\Title('Fehlende Schüler'))
        )))->disableSubmitAction();
    }

    /**
     * @param null $Data
     *
     * @return Stage
     */
    public function frontendInstructionReporting($Data = null)
    {
        $stage = new Stage('Belehrungen', 'Auswertung');

        if ($Data == null && ($tblYearList = Term::useService()->getYearByNow())) {
            $global = $this->getGlobal();

            $tblYear = reset($tblYearList);
            $global->POST['Data']['Year'] = $tblYear->getId();
            $global->POST['Data']['Period'] = SelectBoxItem::PERIOD_FULL_YEAR;

            $global->savePost();
        }

        $stage->setContent(
            new Panel(
                'Filter',
                new Form(new FormGroup(new FormRow(array(
                    new FormColumn((new SelectBox('Data[Year]', 'Schuljahr', array('DisplayName' => Term::useService()->getYearAll())))->setRequired(), 6),
                    new FormColumn(new SelectBox('Data[Type]', 'Schulart', array('Name' => Type::useService()->getTypeAll())), 6),
                    new FormColumn((new Primary('Filtern', '', new Filter()))->ajaxPipelineOnClick(ApiInstructionSetting::pipelineLoadInstructionReportingContent()), 2),
                )))),
                Panel::PANEL_TYPE_INFO
            )
            . ApiInstructionSetting::receiverBlock('', 'InstructionReportingContent')
        );

        return $stage;
    }

    /**
     * @param array|null $Data
     *
     * @return string
     */
    public function loadInstructionReportingTable(?array $Data)
    {
        ini_set('memory_limit', '1G');

        if ($Data === null) {
            return '';
        }
        if (!($tblYear = Term::useService()->getYearById($Data['Year']))) {
            return new \SPHERE\Common\Frontend\Message\Repository\Warning('Bitte wählen Sie ein Schuljahr aus!', new Exclamation());
        }
        if (($tblType = Type::useService()->getTypeById($Data['Type']))) {
            $tblDivisionList = Division::useService()->getDivisionAllByYearAndType($tblYear, $tblType);
        } else {
            $tblDivisionList = Division::useService()->getDivisionAllByYear($tblYear);
        }

        $panelDivisionList = array();
        $tblInstructionList = Instruction::useService()->getInstructionAll();

        if ($tblDivisionList && $tblInstructionList) {
            $tblInstructionList = $this->getSorter($tblInstructionList)->sortObjectBy('Subject');
            $tblDivisionList = $this->getSorter($tblDivisionList)->sortObjectBy('DisplayName', new StringNaturalOrderSorter());
            /** @var TblDivision $tblDivision */
            foreach ($tblDivisionList as $tblDivision) {
                if (Division::useService()->getIsDivisionCourseSystem($tblDivision)) {
                    continue;
                }
                $tblTypeDivision = $tblDivision->getType();
                $contentPanel = array();
                $isDivisionFulfilled = true;
                foreach ($tblInstructionList as $tblInstruction) {
                    $student = '';
                    if (Instruction::useService()->getInstructionItemAllByInstruction($tblInstruction, $tblDivision, null, null)) {
                        if (($missingPersonTotal = Instruction::useService()->getMissingStudentsByInstruction($tblInstruction, $tblDivision, null, null))) {
                            $status = new Warning('Belehrung teilweise durchgeführt');
                            $student = new ToolTip(new Warning(new Disable() . ' ' . count($missingPersonTotal) . ' fehlende' . (count($missingPersonTotal) == 1 ? 'r' : '')
                                . ' Schüler'), implode(' - ', $missingPersonTotal));
                            $isDivisionFulfilled = false;
                        } else {
                            $status = new Success(new Check() . ' Belehrung vollständig durchgeführt');
                        }
                    } else {
                        $status = new \SPHERE\Common\Frontend\Text\Repository\Danger(new Exclamation() . ' Keine Belehrung durchgeführt');
                        $isDivisionFulfilled = false;
                    }

                    $contentPanel[] = new Layout(new LayoutGroup(new LayoutRow(array(
                        new LayoutColumn($tblInstruction->getSubject(), 6),
                        new LayoutColumn($status, 3),
                        new LayoutColumn($student, 3),
                    ))));
                }

                $panelDivisionList[] = new Panel(
                    $tblDivision->getDisplayName() . ($tblTypeDivision ? new Small(' (' . $tblTypeDivision->getName() . ')') : ''),
                    $contentPanel,
                    $isDivisionFulfilled ? Panel::PANEL_TYPE_SUCCESS : Panel::PANEL_TYPE_WARNING
                );
            }
        }

        $layoutGroups = array();
        if (!empty($panelDivisionList)) {
            $layoutGroups[] = new LayoutGroup(new LayoutRow(new LayoutColumn($panelDivisionList)), new Title('Klassen'));
        }

        if (($tblGroupList = Group::useService()->getTudorGroupAll())
            && $tblInstructionList
        ) {
            $tblGroupList = $this->getSorter($tblGroupList)->sortObjectBy('DisplayName', new StringNaturalOrderSorter());
            /** @var TblGroup $tblGroup */
            foreach ($tblGroupList as $tblGroup) {
                if ($tblGroup->getIsGroupCourseSystem()) {
                    continue;
                }
                $contentPanel = array();
                $isGroupFulfilled = true;
                foreach ($tblInstructionList as $tblInstruction) {
                    $student = '';
                    if (Instruction::useService()->getInstructionItemAllByInstruction($tblInstruction, null, $tblGroup, null)) {
                        if (($missingPersonTotal = Instruction::useService()->getMissingStudentsByInstruction($tblInstruction, null, $tblGroup, null))) {
                            $status = new Warning('Belehrung teilweise durchgeführt');
                            $student = new Warning(new Disable() . ' ' . count($missingPersonTotal) . ' fehlende' . (count($missingPersonTotal) == 1 ? 'r' : '')
                                . ' Schüler');
                            $isGroupFulfilled = false;
                        } else {
                            $status = new Success(new Check() . ' Belehrung vollständig durchgeführt');
                        }
                    } else {
                        $status = new \SPHERE\Common\Frontend\Text\Repository\Danger(new Exclamation() . ' Keine Belehrung durchgeführt');
                        $isGroupFulfilled = false;
                    }

                    $contentPanel[] = new Layout(new LayoutGroup(new LayoutRow(array(
                        new LayoutColumn($tblInstruction->getSubject(), 6),
                        new LayoutColumn($status, 3),
                        new LayoutColumn($student, 3),
                    ))));
                }

                $panelGroupList[] = new Panel(
                    $tblGroup->getName(),
                    $contentPanel,
                    $isGroupFulfilled ? Panel::PANEL_TYPE_SUCCESS : Panel::PANEL_TYPE_WARNING
                );
            }
        }

        if (!empty($panelGroupList)) {
            $layoutGroups[] = new LayoutGroup(new LayoutRow(new LayoutColumn($panelGroupList)), new Title('Stammgruppen'));
        }

        if (!empty($layoutGroups)) {
            return new Layout($layoutGroups);
        }

        return new \SPHERE\Common\Frontend\Message\Repository\Warning('Keine Daten gefunden', new Exclamation());
    }
}