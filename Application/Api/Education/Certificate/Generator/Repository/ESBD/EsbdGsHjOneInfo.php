<?php
namespace SPHERE\Application\Api\Education\Certificate\Generator\Repository\ESBD;

use SPHERE\Application\Education\Certificate\Generator\Repository\Element;
use SPHERE\Application\Education\Certificate\Generator\Repository\Page;
use SPHERE\Application\Education\Certificate\Generator\Repository\Section;
use SPHERE\Application\Education\Certificate\Generator\Repository\Slice;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;

/**
 * Class EsbdGsHjOneInfo
 *
 * @package SPHERE\Application\Api\Education\Certificate\Certificate\Repository\ESBD
 */
class EsbdGsHjOneInfo extends EsbdStyle
{

    /**
     * @param TblPerson|null $tblPerson
     * @return Page
     * @internal param bool $IsSample
     *
     */
    public function buildPages(TblPerson $tblPerson = null){

        $personId = $tblPerson ? $tblPerson->getId() : 0;

        return (new Page())
            ->addSlice($this->getEsbdHeadSlice('Evangelisches Schulzentrum Bad Düben - Grundschule'))
            ->addSlice($this->getCertificateHead('Halbjahresinformation der Grundschule', '5px'))
            ->addSlice($this->getDivisionAndYear($personId, '15px'))
            ->addSlice($this->getStudentName($personId))
            ->addSlice($this->getDescriptionContent($personId, '600px', '20px'))
            ->addSlice((new Slice())
                ->addSection((new Section())
                    ->addElementColumn((new Element())
                        ->setContent('Fehltage entschuldigt:')
                        , '22%')
                    ->addElementColumn((new Element())
                        ->setContent('{% if(Content.P' . $personId . '.Input.Missing is not empty) %}
                                        {{ Content.P' . $personId . '.Input.Missing }}
                                    {% else %}
                                        &nbsp;
                                    {% endif %}')
                        , '20%')
                    ->addElementColumn((new Element())
                        ->setContent('Fehltage unentschuldigt:')
                        , '25%')
                    ->addElementColumn((new Element())
                        ->setContent('{% if(Content.P' . $personId . '.Input.Bad.Missing is not empty) %}
                                        {{ Content.P' . $personId . '.Input.Bad.Missing }}
                                    {% else %}
                                        &nbsp;
                                    {% endif %}')
                    )
                )
                ->styleMarginTop('15px')
            )
            ->addSlice($this->getDateLine($personId))
            ->addSlice($this->getSignPart($personId, false))
            ->addSlice($this->getParentSign())
            ->addSlice((new Slice())->addElement(
                ($this->getEsbdBottomLine()))
            );
    }
}
