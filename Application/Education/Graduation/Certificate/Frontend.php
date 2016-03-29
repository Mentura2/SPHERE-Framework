<?php
namespace SPHERE\Application\Education\Graduation\Certificate;

use MOC\V\Component\Document\Component\Bridge\Repository\DomPdf;
use MOC\V\Component\Document\Component\Parameter\Repository\FileParameter;
use SPHERE\Application\Document\Explorer\Storage\Storage;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Document;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Element;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Frame;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Page;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Section;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Slice;
use SPHERE\Application\Education\Lesson\Division\Division;
use SPHERE\Application\Education\Lesson\Division\Service\Entity\TblDivisionStudent;
use SPHERE\Application\People\Meta\Student\Student;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;
use SPHERE\Application\People\Search\Group\Group;
use SPHERE\Common\Frontend\Form\Repository\Button\Primary;
use SPHERE\Common\Frontend\Form\Repository\Field\TextField;
use SPHERE\Common\Frontend\Form\Structure\Form;
use SPHERE\Common\Frontend\Form\Structure\FormColumn;
use SPHERE\Common\Frontend\Form\Structure\FormGroup;
use SPHERE\Common\Frontend\Form\Structure\FormRow;
use SPHERE\Common\Frontend\Icon\Repository\ChevronRight;
use SPHERE\Common\Frontend\Icon\Repository\Person;
use SPHERE\Common\Frontend\IFrontendInterface;
use SPHERE\Common\Frontend\Layout\Repository\Panel;
use SPHERE\Common\Frontend\Layout\Repository\Title;
use SPHERE\Common\Frontend\Layout\Structure\Layout;
use SPHERE\Common\Frontend\Layout\Structure\LayoutColumn;
use SPHERE\Common\Frontend\Layout\Structure\LayoutGroup;
use SPHERE\Common\Frontend\Layout\Structure\LayoutRow;
use SPHERE\Common\Frontend\Link\Repository\Standard;
use SPHERE\Common\Frontend\Message\Repository\Warning;
use SPHERE\Common\Frontend\Table\Structure\TableData;
use SPHERE\Common\Window\Stage;
use SPHERE\System\Cache\Handler\TwigHandler;
use SPHERE\System\Extension\Extension;

class Frontend extends Extension implements IFrontendInterface
{

    public function frontendStudent()
    {

        $Stage = new Stage('Schüler', 'wählen');

        $tblGroup = Group::useService()->getGroupByMetaTable('STUDENT');

        $StudentTable = array();
        if ($tblGroup) {
            $tblPersonAll = Group::useService()->getPersonAllByGroup($tblGroup);
            if ($tblPersonAll) {
                array_walk($tblPersonAll, function (TblPerson $tblPerson) use (&$StudentTable) {

                    $tblDivisionStudent = Division::useService()->getDivisionStudentAllByPerson($tblPerson);
                    if ($tblDivisionStudent) {
                        array_walk($tblDivisionStudent,
                            function (TblDivisionStudent $tblDivisionStudent) use (&$StudentTable, $tblPerson) {

                                $tblDivision = $tblDivisionStudent->getTblDivision();

                                $StudentTable[] = array(
                                    'Division' => $tblDivision->getDisplayName(),
                                    'Student'  => $tblPerson->getLastFirstName(),
                                    'Option'   => new Standard(
                                        'Weiter', '/Education/Graduation/Certificate/Template', new ChevronRight(),
                                        array(
                                            'Id' => $tblDivisionStudent->getId()
                                        ), 'Auswählen')
                                );
                            }
                        );
                    }
                });
            } else {
                // TODO: Error
            }

            $Stage->setContent(
                new TableData($StudentTable)
            );

        } else {
            // TODO: Error
        }

        return $Stage;
    }

    /**
     * @param null|int $Id TblDivisionStudent
     *
     * @return Stage
     */
    public function frontendTemplate($Id = null)
    {

        $Stage = new Stage('Vorlage', 'wählen');

        if ($Id) {
            $tblDivisionStudent = Division::useService()->getDivisionStudentById($Id);
            if ($tblDivisionStudent) {
                $tblPerson = $tblDivisionStudent->getServiceTblPerson();
                if ($tblPerson) {
                    $tblStudent = Student::useService()->getStudentByPerson($tblPerson);
                    if ($tblStudent) {
                        $tblStudentTransferType = Student::useService()->getStudentTransferTypeByIdentifier('PROCESS');
                        $tblStudentTransfer = Student::useService()->getStudentTransferByType(
                            $tblStudent, $tblStudentTransferType
                        );
                        if ($tblStudentTransfer) {
                            // TODO: Find Templates in Database (DMS)

                            $TemplateTable[] = array(
                                'Template' => 'Hauptschulzeugnis',
                                'Option'   => new Standard(
                                    'Weiter', '/Education/Graduation/Certificate/Data', new ChevronRight(), array(
                                    'Id'       => $tblDivisionStudent->getId(),
                                    'Template' => 1
                                ), 'Auswählen')
                            );

                            $Stage->setContent(
                                new Layout(array(
                                    new LayoutGroup(new LayoutRow(
                                        new LayoutColumn(array(
                                            new Panel('Aktuelle Schule: ', array(
                                                ( $tblStudentTransfer->getServiceTblCompany() ? $tblStudentTransfer->getServiceTblCompany()->getName() : 'Schule' )
                                            )),
                                            new Panel('Aktuelle Schulart: ', array(
                                                ( $tblStudentTransfer->getServiceTblType() ? $tblStudentTransfer->getServiceTblType()->getName() : 'Schulart' )
                                            )),
                                            new Panel('Aktueller Bildungsgang: ', array(
                                                ( $tblStudentTransfer->getServiceTblCourse() ? $tblStudentTransfer->getServiceTblCourse()->getName() : 'Abschluss' )
                                            )),
                                        ))
                                    ), new Title('Schüler-Informationen')),
                                    new LayoutGroup(new LayoutRow(
                                        new LayoutColumn(
                                            new TableData($TemplateTable)
                                        )
                                    ), new Title('Verfügbare Vorlagen')),
                                ))
                            );

                        } else {
                            $Stage->setContent(
                                new Warning('Vorlage kann nicht gewählt werden, da dem Schüler in der Schülerakte keine aktuelle Schulart zugewiesen wurde.')
                            );
                        }
                    } else {
                        $Stage->setContent(
                            new Warning('Vorlage kann nicht gewählt werden, da dem Schüler keine Schülerakte zugewiesen wurde.')
                            .new Standard('Zum Schüler', '/People/Person', new Person(),
                                array('Id' => $tblPerson->getId()))
                        );
                    }
                } else {
                    // TODO: Error
                }
            } else {
                $Stage->setContent(
                    new Warning('Vorlage kann nicht gewählt werden, da dem Schüler keine Klasse zugewiesen wurde.')
                );
            }
        } else {
            // TODO: Error
        }

        return $Stage;
    }

    /**
     * @param null|int $Id TblDivisionStudent
     * @param          $Template
     *
     * @return Stage
     */
    public function frontendData($Id, $Template)
    {

        $Stage = new Stage('Daten', 'eingeben');

        if ($Id) {
            $tblDivisionStudent = Division::useService()->getDivisionStudentById($Id);
            if ($tblDivisionStudent) {
                $tblPerson = $tblDivisionStudent->getServiceTblPerson();
                if ($tblPerson) {
                    $tblStudent = Student::useService()->getStudentByPerson($tblPerson);
                    if ($tblStudent) {

                        $tblStudentTransferType = Student::useService()->getStudentTransferTypeByIdentifier('PROCESS');
                        $tblStudentTransfer = Student::useService()->getStudentTransferByType(
                            $tblStudent, $tblStudentTransferType
                        );
                        if ($tblStudentTransfer) {

                            $tblPerson = $tblStudent->getServiceTblPerson();
                            $tblDivision = $tblDivisionStudent->getTblDivision();
                            $tblYear = $tblDivision->getServiceTblYear();

                            $Global = $this->getGlobal();
                            $Global->POST['Data']['School']['Name'] = ( $tblStudentTransfer->getServiceTblCompany() ? $tblStudentTransfer->getServiceTblCompany()->getName() : 'Schule' );
                            $Global->POST['Data']['School']['Type'] = ( $tblStudentTransfer->getServiceTblType() ? $tblStudentTransfer->getServiceTblType()->getName() : 'Schulart' );
                            $Global->POST['Data']['School']['Course'] = ( $tblStudentTransfer->getServiceTblCourse() ? $tblStudentTransfer->getServiceTblCourse()->getName() : 'Abschluss' );
                            $Global->POST['Data']['School']['Year'] = $tblYear->getName();
                            $Global->POST['Data']['Name'] = $tblPerson->getLastFirstName();
                            $Global->POST['Data']['Division'] = $tblDivision->getDisplayName();
                            $Global->savePost();

                            $Stage->setContent(
                                new Layout(array(
                                    new LayoutGroup(new LayoutRow(
                                        new LayoutColumn(array(
                                            new Panel('Aktuelle Schule: ', array(
                                                ( $tblStudentTransfer->getServiceTblCompany() ? $tblStudentTransfer->getServiceTblCompany()->getName() : 'Schule' )
                                            )),
                                            new Panel('Aktuelle Schulart: ', array(
                                                ( $tblStudentTransfer->getServiceTblType() ? $tblStudentTransfer->getServiceTblType()->getName() : 'Schulart' )
                                            )),
                                            new Panel('Aktueller Bildungsgang: ', array(
                                                ( $tblStudentTransfer->getServiceTblCourse() ? $tblStudentTransfer->getServiceTblCourse()->getName() : 'Abschluss' )
                                            )),
                                        ))
                                    ), new Title('Schüler-Informationen')),
                                    new LayoutGroup(new LayoutRow(
                                        new LayoutColumn(
                                            new Form(
                                                new FormGroup(
                                                    new FormRow(array(
                                                        new FormColumn(
                                                            new Panel('Schuldaten', array(
                                                                (new TextField('Data[School][Name]', 'Schule',
                                                                    'Schule')),
                                                                (new TextField('Data[School][Type]', 'Schulart',
                                                                    'Schulart')),
                                                                (new TextField('Data[School][Course]', 'Bildungsgang',
                                                                    'Bildungsgang')),
                                                                (new TextField('Data[School][Year]', 'Schuljahr',
                                                                    'Schuljahr')),
                                                            )), 4),
                                                        new FormColumn(
                                                            new Panel('Schüler', array(
                                                                (new TextField('Data[Name]', 'Name', 'Name')),
                                                                (new TextField('Data[Division]', 'Klasse', 'Klasse')),
                                                            )), 4),
                                                    ))
                                                )
                                                , new Primary('Vorschau erstellen'),
                                                '/Education/Graduation/Certificate/Create',
                                                array('Template' => $Template))
                                        )
                                    ), new Title('Verfügbare Daten-Felder')),
                                ))
                            );
                        } else {
                            // TODO: Error
                        }
                    } else {
                        // TODO: Error
                    }
                } else {
                    // TODO: Error
                }
            } else {
                // TODO: Error
            }
        } else {
            // TODO: Error
        }
        return $Stage;
    }

    public function frontendCreate($Data, $Content = null)
    {

        // TODO: Find Template in Database (DMS)
        $this->getCache(new TwigHandler())->clearCache();

        $Header = (new Slice())
            ->addSection((new Section())
                ->addElementColumn((new Element())
                    ->setContent('HorJEins.pdf')
                    ->styleTextSize('12px')
                    ->styleTextColor('#CCC')
                    ->styleAlignCenter()
                    , '25%')
                ->addElementColumn((new Element\Sample())
                    ->styleTextSize('30px')
                )
                ->addElementColumn((new Element())
                    , '25%')
            );

        $Content = (new Frame())->addDocument(
            (new Document())
                ->addPage((new Page())
                    ->addSlice(
                        $Header
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element\Image('/Common/Style/Resource/Logo/Hormersdorf_logo.png', '150px'))
                                ->styleAlignCenter()
                                , '25%')
                            ->addSliceColumn((new Slice())
                                ->addSection((new Section())
                                    ->addElementColumn((new Element())
                                        ->setContent('Name der Schule:')
                                        ->styleTextSize('11px')
                                        ->styleMarginTop('6px')
                                        , '20%')
                                    ->addElementColumn((new Element())
                                        ->setContent('Freie Evangelische Grundschule Hormersdorf')
                                        ->styleTextSize('17px')
                                        ->styleTextBold()
                                        ->styleBorderBottom('1px', '#BBB')
                                        ->styleAlignCenter()
                                        , '80%')
                                )
                                ->addSection((new Section())
                                    ->addElementColumn((new Element())
                                        , '27%')
                                    ->addElementColumn((new Element())
                                        ->setContent('(Staatlich anerkannte Ersatzschule)')
                                        ->styleAlignCenter()
                                        , '73%')
                                )
                                ->styleMarginTop('30px')
                                , '75%')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('HALBJAHRESINFORMATION DER GRUNDSCHULE')
                            ->styleTextSize('24px')
                            ->styleTextBold()
                            ->styleAlignCenter()
                            ->styleMarginTop('20px')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Klasse')
                                ->styleBorderBottom('1px', '#BBB')
                                , '8%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.Division }}')
                                ->styleBorderBottom('1px', '#BBB')
                                , '47%')
                            ->addElementColumn((new Element())
                                ->setContent('1. Schulhalbjahr')
                                ->styleBorderBottom('1px', '#BBB')
                                ->styleAlignRight()
                                , '30%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.School.Year }}')
                                ->styleBorderBottom('1px', '#BBB')
                                ->styleAlignCenter()
                                , '15%')
                        )->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Vor- und Zuname:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '20%')
                            ->addElementColumn((new Element())
                                ->setContent('{{ Data.Name }}')
                                ->styleBorderBottom('1px', '#BBB')
                                , '80%')
                        )->styleMarginTop('5px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Betragen')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('Mitarbeit')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('15px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Fleiß')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('Ordnung')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('7px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Notenstufen:
                                1 = sehr gut, 2 = gut, 3 = befriedigend, 4 = ausreichend, 5 = mangelhaft, 6 = ungenügend')
                                ->styleTextSize('8px')
                                ->styleMarginTop('15px')
                                , '30%')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Leistungen in den einzelnen Fächern')
                            ->styleMarginTop('20px')
                            ->styleTextBold()
                            ->styleTextItalic()
                        )
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Deutsch')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('Mathematik')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('20px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Sachunterricht')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('Werken')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('7px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Kunst')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('EV. Religion')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('7px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Musik')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '4%')
                            ->addElementColumn((new Element())
                                ->setContent('Sport')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                        )
                        ->styleMarginTop('7px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Englisch')
                                ->stylePaddingTop()
                                , '33%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleAlignCenter()
                                ->styleBackgroundColor('#CCC')
                                ->stylePaddingTop()
                                ->stylePaddingBottom()
                                , '15%')
                            ->addElementColumn((new Element())
                                , '52%')
                        )
                        ->styleMarginTop('7px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Notenstufen:
                                1 = sehr gut, 2 = gut, 3 = befriedigend, 4 = ausreichend, 5 = mangelhaft, 6 = ungenügend')
                                ->styleTextSize('8px')
                                ->styleMarginTop('15px')
                                , '30%')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Bemerkungen:')
                            ->styleTextBold()
                            ->styleTextItalic()
                            ->styleMarginTop('20px')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx
                                Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx Mustertext xxx ')
                            ->styleMarginTop('5px')
                        )
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Fehltage entschuldigt:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '23%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '10%')
                            ->addElementColumn((new Element())
                                ->setContent('unentschuldigt:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '17%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '50%')
                        )->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                ->setContent('Datum:')
                                ->styleBorderBottom('1px', '#BBB')
                                , '10%')
                            ->addElementColumn((new Element())
                                ->setContent('23.03.2016')
                                ->styleAlignCenter()
                                ->styleBorderBottom('1px', '#BBB')
                                , '25%')
                            ->addElementColumn((new Element())
                                , '65%')
                        )->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                , '35%')
                            ->addElementColumn((new Element())
                                ->setContent('Dienststempel der Schule')
                                ->styleTextSize('9px')
                                ->styleAlignCenter()
                                , '30%')
                            ->addElementColumn((new Element())
                                ->setContent('&nbsp;')
                                ->styleBorderBottom('1px', '#BBB')
                                , '35%')
                        )
                        ->addSection((new Section())
                            ->addElementColumn((new Element())
                                , '35%')
                            ->addElementColumn((new Element())
                                , '30%')
                            ->addElementColumn((new Element())
                                ->setContent('Klassenlehrer/in')
                                ->styleAlignCenter()
                                ->styleTextSize('11px')
                                , '35%')
                        )
                        ->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Zur Kenntnis genommen:')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                        ->styleMarginTop('30px')
                    )
                    ->addSlice((new Slice())
                        ->addElement((new Element())
                            ->setContent('Personensorgeberechtigte/r')
                            ->styleTextSize('11px')
                            ->styleAlignCenter()
                        )
                    )
                )
        );

        $Content->setData($Data);

        $Preview = $Content->getContent();

//        $FileLocation = Storage::useWriter()->getTemporary('pdf', 'Zeugnistest-'.date('Ymd-His'), true);
//        /** @var DomPdf $Document */
//        $Document = \MOC\V\Component\Document\Document::getPdfDocument($FileLocation->getFileLocation());
//        $Document->setContent($Content->getTemplate());
//        $Document->saveFile(new FileParameter($FileLocation->getFileLocation()));

        $Stage = new Stage();

        $Stage->setContent(new Layout(new LayoutGroup(new LayoutRow(array(
            new LayoutColumn(array(
//                $FileLocation->getFileLocation(),
                '<div class="cleanslate">'.$Preview.'</div>'
            ), 12),
//            new LayoutColumn(array(
//                '<pre><code class="small">'.( str_replace("\n", " ~~~ ",
//                    file_get_contents($FileLocation->getFileLocation())) ).'</code></pre>'
//                FileSystem::getDownload($FileLocation->getRealPath(),
//                    "Zeugnis ".date("Y-m-d H:i:s").".pdf")->__toString()
//            ), 6),
        )))));

        return $Stage;
    }
}